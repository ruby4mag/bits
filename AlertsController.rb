class AlertsController < ApplicationController
        protect_from_forgery unless: -> { request.format.json? }
        before_action :authenticate_user!, except: [ :create, :downloadxlsx, :getClosedEvents,:getEventById  ]
        before_action :set_event, only: [:show, :edit, :update, :destroy]
        skip_before_action :verify_authenticity_token
        load_and_authorize_resource
        layout "empty", only: [:show]

        def api_request?
                request.format.json?
        end

        # GET /events
        # GET /events.json
        def index
                respond_to do |format|
                        format.html { @events = Event.all }
                        format.json { render json: EventsDatatable.new(view_context) }
                end
        end

        def dropped
                respond_to do |format|
                format.html { @events = Event.all }
                format.json { render json: EventsDatatable.new(view_context) }
                end
        end


        def sendEmail
                eventID = params[:eventid]
                emailID = params[:emailid]
                emailCC = params[:emailcc]
                emailTEXT = params[:emailtext]
                @event = Event.find(eventID)
                @event.worklogs.create(:user => current_user.login , :comment => "Email triggered to #{emailID}")
                render :json => {"status" => "OK"}
        end

        def sendAutoEmail(eventID,emailID,emailFrom,emailCC,emailTEXT,orule_name)
                        logger.debug("Event ID is #{eventID}")
                        @event = Event.find(eventID)
                        if emailID.blank?
                                #use the recepients from eventGroups
                                emailID = @event['eventGroups']
                        end
                        if emailID.blank?
                                # email still blank. Use default
                                emailID = 'maging@alertman.com'
                        end
                        @event.worklogs.create(:user => 'AlertMan System', :comment => "Auto Email triggered to #{emailID} by notification rule #{orule_name}")
        end

        def sendSingleEmail(eventIDs,emailID,emailCC,email_subject,emailTEXT)
                        logger.debug("Event IDs are #{eventIDs.to_s}")
                        if emailID.blank?
                                #use the recepients from eventGroups
                                emailID = ''
                        end
                        if emailCC.blank?
                                # email still blank. Use default
                                emailCC = ''
                        end
        end

        def sendPagerduty(eventid = nil, pdService = nil , pdEpolicy = nil )
                eventID = eventid.nil? ? params[:eventid] : eventid
                @event = Event.find(eventID)
                begin

                        pdService = pdService.nil? ? params[:pdService] : pdService
                        pdEpolicy = pdEpolicy.nil? ? params[:pdEpolicy] : pdEpolicy
                        logger.debug("  pdService #{pdService}  ")
                        logger.debug("  pdEpolicy #{pdEpolicy}  ")
                        pdpayload = preparePdMarkdown(@event)
                        payload = "{
                                        \"incident\": {
                                                \"type\": \"incident\",
                                                \"title\": \"#{sanitizeS(@event['alertSummary'])}\",
                                                \"service\": {
                                                \"id\": \"#{pdService}\",
                                                \"type\": \"service_reference\"
                                        },
                                        \"priority\": {
                                                \"id\": \"#{AppConstants::PD_PRIORITY}\",
                                                \"type\": \"priority_reference\"
                                        },
                                        \"urgency\": \"high\",
                                        \"incident_key\": \"#{@event['eventID']}\",
                                        \"body\": {
                                                \"type\": \"incident_body\",
                                                \"details\": \"#{pdpayload}\"
                                        },
                                        \"escalation_policy\": {
                                                \"id\": \"#{pdEpolicy}\",
                                                \"type\": \"escalation_policy_reference\"
                                        }
                                }
                        }"
                        logger.debug("PD Payload is : #{payload}")

                        require 'net/http'
                        require 'uri'
                        require 'json'

                        uri = URI.parse("https://api.pagerduty.com/incidents")
                        request = Net::HTTP::Post.new(uri)
                        request.content_type = "application/json"
                        request["Accept"] = "application/vnd.pagerduty+json;version=2"
                        request["From"] = "#{AppConstants::PD_USER}"
                        request["Authorization"] = "Token token=#{AppConstants::PD_TOKEN}"
                        request.body = payload

                        req_options = {
                                use_ssl: uri.scheme == "https",
                        }

                        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
                                http.request(request)
                        end

                        logger.debug ("  RESPONSE #{response.body}")
                        pdresponse = JSON.parse(response.body)

                        if current_user.nil?
                                repuser = 'AlertMan System'
                        else
                                repuser = current_user.login
                        end
                        if ! pdresponse['incident'].nil?
                                @event.push(tickets: pdresponse['incident']['incident_number'])
                                @event.worklogs.create(:user => repuser , :comment => "PD incident #{pdresponse['incident']['incident_number']} created ")
                                if ! current_user.nil?
                                        render :json => {"status" => "OK", "ticket" => pdresponse['incident']['incident_number'] }
                                end
                        else
                                @event.worklogs.create(:user => repuser , :comment => "PD incident creation failed! \n #{response.body}")
                                if ! current_user.nil?
                                        render :json => {"status" => "error"}
                                end
                        end
                rescue => e
                        if current_user.nil?
                                repuser = 'AlertMan System'
                        else
                                repuser = current_user.login
                        end

                        @event.worklogs.create(:user => repuser , :comment => "PD incident creation failed! \n #{e.message}")
                        if ! current_user.nil?
                                render :json => {"status" => "error"}
                        end
                end
        end

        def getpdservicelist
                select_string = ''
                pd  = Pagerduty.first
                pdservice = pd['impactedService']
                pdo = JSON.parse(pdservice)
                pdo['services'].each do |service|
                        select_string+= " <option value=#{service['id']}>#{service['name']}</option>"
                end
                render plain: select_string
        end

        def getpdepolicylist
                select_string = ''
                pd  = Pagerduty.first
                pdepolicy = pd['assignTo']
                pdo = JSON.parse(pdepolicy)
                pdo['escalation_policies'].each do |epolicy|
                select_string+= " <option value=#{epolicy['id']}>#{epolicy['name']}</option>"
                end
                render plain: select_string
        end

        def api
                respond_to do |format|
                        format.html { @events = Event.read(mode: :secondary_preferred).all }
                        format.json {  }
                end
        end

        def check_event_flap(raw_event)
                flapping_event = 0
                logger.debug("Raw event is #{raw_event}  ")
                flaprules = Frule.all
                flaprules.each do |flaprule|
                        rulematched = 0
                        evaluator = JqueryQueryBuilder::Evaluator.new(flaprule['rule'])
                        rulematched = evaluator.object_matches_rules?(raw_event)
                        if ! rulematched
                                logger.debug('Flap detection rule '+ flaprule['name'] + ' not matched')
                                next
                        else
                                logger.debug('Flap detection rule '+ flaprule['name'] + ' matched')
                                # check for event matching the action conditions.
                                fields = flaprule.comparefields.reject {|field| field.empty?}
                                # Search in child events only.
                                fevent = Event.where( :lastTime.gte => ( DateTime.parse(raw_event['firstTime']) - flaprule['alertage'].second ), :alertSummary.nin => [/Grouped Alert for pattern/], :dropped => 'NO')
                                fields.each do |fname|
                                        logger.debug("Checking #{fname}  ")
                                        fevent = fevent.where(fname.to_sym => raw_event[fname])
                                end
                                latest_event = fevent.order("lastTime DESC").first
                                if latest_event
                                        logger.debug("Latest event is #{latest_event['id']}  ")
                                        old_eventid = latest_event['eventID']
                                        old_event_count = latest_event['eventCount']
                                        # check if the alert is within alert age
                                        if raw_event['firstTime'] < (latest_event['lastTime' ] + flaprule['alertage'] ) && latest_event['dropped'] == 'NO' && latest_event['eventStatus'] != "OPEN"
                                                ## Need to add the suppression check logic here.
                                                ##def blackedout?(event)
                                                        suppressions = suppression.where(disabled: { :$in => [nil,false] }).order('indexorder ASC')
                                                        # suppression Rule Matching
                                                        dropped = 0
                                                        bl_name = ''
                                                        tmp_event = raw_event
                                                        tmp_event['firstTime1'] = raw_event['firstTime']
                                                        tmp_event['firstTime2'] = raw_event['firstTime']
                                                        logger.debug(" #{tmp_event}  ")

                                                        suppressions.each do |suppression|
                                                                logger.debug( "Processing  #{suppression['name']}")
                                                                begin
                                                                        evaluator = JqueryQueryBuilder::Evaluator.new(suppression['rule'])
                                                                        @match_events = evaluator.get_matching_objects([raw_event])
                                                                        if @match_events.blank?
                                                                                logger.debug('suppression Rule '+ suppression['name'] + ' not matched')
                                                                        else
                                                                                logger.debug( 'suppression Rule '+suppression['name'] + ' matched')
                                                                                ## event.set(:eventStatus => 'CLEARED', :suppressionId => suppression['id'], :suppressionName => suppression['name'], :dropped => "YES")
                                                                                dropped = 1
                                                                                bl_name = suppression['name']
                                                                                break
                                                                        end
                                                                rescue => error
                                                                        logger.error("  Error processing suppression #{suppression['name']} -- #{error.message}")
                                                                end
                                                        end
                                                        ##return dropped,bl_name,event
                                                ##end

                                                if dropped == 1
                                                        logger.debug("The alert is to be suppressed. Not reopening event")
                                                        next
                                                end

                                                logger.debug("Event to be repopened")
                                                # Previous alert need to be reopened and unacknowledged
                                                # LOGIC : Need to check for the staged events. Staged events will have stageDuration set
                                                staged = false
                                                if (! latest_event['stageDuration'].nil?) && Time.now.utc.to_i > latest_event['stageDuration']
                                                        latest_event.worklogs.each do |wl|
                                                                if wl.comment.include?("Changing severity")
                                                                        staged = true
                                                                        logger.debug("Event is in stage")
                                                                        break
                                                                end
                                                        end
                                                end
                                                updateparams = {}
                                                updateparams['eventStatus'] = "OPEN"
                                                updateparams['eAck'] = "NO"
                                                updateparams['lastTime'] = raw_event['firstTime']
                                                updateparams['eventID'] = raw_event['eventID']
                                                updateparams['eventCount'] = old_event_count.nil? ? 1 : old_event_count +  1
                                                updateparams['severity'] = "CRITICAL" if staged

                                                latest_event.update(updateparams)
                                                latest_event.worklogs.create(:user => 'System', :comment => "#{flaprule['name']} :  Reopening event #{latest_event['id']} as the latest alert is within alert age. Updating old eventID #{old_eventid} with new #{raw_event['eventID'] }")
                                                flapping_event = 1
                                                # Check if this alert is a child alert. If yes, open the parent alert as well.
                                                if ! latest_event['incId'].nil?
                                                        logger.debug("This is a child alert. Parent alert need to be reopened")
                                                        parent_event = Event.find(latest_event['incId'])
                                                        logger.debug("----------- In Repoen Latest event is #{latest_event['id']}")
                                                        parent_event.add_to_set(groupevents: latest_event['id'])
                                                        parent_event.worklogs.create(:user => 'System', :comment => "Reopening Child alert <a target='_blank' href='/events/#{latest_event['id']}'> #{latest_event['id']}</a> due to flap rule - #{flaprule['name']} ")
                                                        if parent_event['eventStatus'] ==  "CLEARED"
                                                                logger.debug("Parent is in cleared state. So reopen")
                                                                updateparams = {}
                                                                updateparams['eventStatus'] = "OPEN"
                                                                updateparams['eAck'] = "NO"
                                                                updateparams['lastTime'] = raw_event['firstTime']
                                                                updateparams['severity'] = "CRITICAL" if staged
                                                                parent_event.update(updateparams)
                                                                parent_event.worklogs.create(:user => 'System', :comment => "Reopening Parent alert as the one of the child alert <a target='_blank' href='/events/#{latest_event['id']}'> #{latest_event['id']}</a> is reopened")
                                                                if staged
                                                                        parent_event.worklogs.create(:user => 'System', :comment => "Changing severity of parent alert to CRITICAL as the child event has exceeded the delay time")
                                                                end
                                                        else
                                                                logger.debug("Parent is NOT in cleared state.")
                                                        end
                                                else
                                                        logger.debug("This is NOT a child alert")
                                                end
                                                break
                                        end
                                else
                                        logger.debug("No Maching Flapping eventrule found ")
                                end
                        end
                end
                return flapping_event
        end

        def unack_alerts
                @unack_count = Event.read(mode: :secondary_preferred).where(:severity => 'CRITICAL' , :eventStatus => 'OPEN', :eAck.ne => 'YES', :incId => nil).count
                respond_to do |format|
                        format.html {  }
                        format.json {  }
                end
        end

        def dropped_alerts
                @dropped_count = Event.read(mode: :secondary_preferred).where(:severity => 'CRITICAL' , :eventStatus => 'DROPPED').count
                respond_to do |format|
                        format.html {  }
                        format.json {  }
                end
        end

        def getEventById
                        eventID = params[:eventID]
                @eventsWithID = Event.read(mode: :secondary_preferred).where(:eventID => eventID)
                        render :json => @eventsWithID
        end

        def checkCriticalEvents
                error = 0
                count = 0
                bls = []
                status = 0
                if Event.where(:severity => "CRITICAL",:dropped => "NO",:firstTime.gte => DateTime.now.utc - 60.minutes).count == 0
                        bls = Event.collection.aggregate([{ "$match": {"firstTime": { "$gte": DateTime.now.utc - 60.minutes},"severity": "CRITICAL","suppressionName": { "$nin": [nil,""]}}},{"$group"=>{ :_id=> "$suppressionName" , :count=>{"$sum"=>1} } } ]).to_a               #       # check the latest dropped events in last x minutes and get the suppression names.
                        status = 1
                end
                table = '<table class=\'table-bordered\'><tr><th style=\'width:300px;text-align: center;\'>Alert Suppression</th><th style=\'text-align: center;\'>count</th></tr>'

                bls.each do |row|
                        table += "<tr><td>#{row['_id']}</td><td style='text-align: center;'>#{row['count']}</td></tr>"
                end
                table += '</table >'
                table.gsub!('"','')
                respond_to do |format|
                        format.html {  }
                        format.json {  render :json => "{\"status\" : #{status} , \"count\" : #{bls.length} , \"broken\" : \"#{table}\" }"}
                end
        end


        def getHeartbeat
                        error = 0
                        count = 0
                        broken_sources = []
                heartbeats = Heartbeat.read(mode: :secondary_preferred).where(:enabled => true)
                        heartbeats.each do |heartbeat|
                                if ( (Time.now.utc - heartbeat.lastEvent).to_i > heartbeat.threshold )
                                        error = 1
                                        count += 1
                                        broken_sources.push(heartbeat.eventSource)
                                        # log it
                                        logger.debug("Integration Broken: eventSource - #{heartbeat.eventSource} , lastEvent - #{heartbeat.lastEvent} , threshold - #{heartbeat.threshold}")
                                end
                        end

                respond_to do |format|
                format.html {  }
                format.json {  render :json => "{\"status\" : #{error} , \"count\" : #{count} , \"broken\" : #{broken_sources} }"}
                end
        end

        def download
                events = downloadCsv(params['filter'])
                respond_to do |format|
                        format.html { send_data events , :filename => "event_report_#{DateTime.now().strftime("%F_%T")}.csv", :type => 'text/csv'  }
                        format.json { send_data events , :filename => "event_report_#{DateTime.now().strftime("%F_%T")}.csv", :type => 'text/csv' }
                end
        end

        def getClosedEvents
                eventSource = params[:eventSource]
                eventIds = params[:eventIds]
                closedEvents = Event.read(mode: :secondary_preferred).where(:eventSource => eventSource, :eventStatus.ne => "CLEARED", :eventID.nin => eventIds,:alertSummary.nin => [/Grouped Alert for pattern/]).pluck("eventID")
                render :json => closedEvents
        end

        def show
                @tickets = ''
                if ! @event['tickets'].nil?
                        if ! @event['tickets'].blank?
                                @event['tickets'].each do |ticket|
                                        if ! ticket.nil?
                                                ticket = ticket.to_s
                                                if ticket.start_with?('TKT')
                                                                @tickets = @tickets+'<span class="label label-info" style="margin:3px;"><a target="_blank" href="'+ AppConstants::CO_TKT_WEB_URL + ticket +'">' + ticket + '</a></span>'
                                                elsif (ticket.start_with?('ITSD') or ticket.start_with?('CSSD'))
                                                                @tickets = @tickets+'<span class="label label-info" style="margin:3px;"><a target="_blank" href="https://'+AppConstants::JSD_HOSTNAME+'/browse/'+ ticket+'">'+ ticket+ '</a></span>'
                                                else
                                                                @tickets = @tickets+'<span class="label label-info" style="margin:3px;"><a target="_blank" href="https://'+AppConstants::PD_HOST+'/incidents/'+ ticket+'">'+ ticket+ '</a></span>'
                                                end
                                        end
                                end
                        end
                end
        end

        # GET /events/new
        def new
                @event = Event.new
        end

        # GET /events/1/edit
                def edit
        end

        def check_corel(event)
                corels = Corelrule.all
                corels.each do |corel|
                        evaluator = JqueryQueryBuilder::Evaluator.new(corel['rule'])
                        @match_events = evaluator.get_matching_objects([event.to_h])
                        if @match_events.blank?
                                logger.debug('Corel Rule '+ corel['name'] + ' not matched')
                                next
                        else
                                logger.debug('Corel Rule '+ corel['name'] + ' matched')
                                key_array = []
                                key_hash = {}
                                key_name = corel['corelentity']
                                corel['corelvalues'].each do |factor|
                                        key_array.push(factor[0])
                                        key_hash[factor[0]] = factor[1]
                                end
                                logger.debug("  #{key_name}  #{key_array}  ")
                                logger.debug("  #{event[key_name]}  #{key_array}  ")
                                if ! key_array.include?(event[key_name])
                                        next
                                end
                                if corel['unstage'] == true
                                        existing_open_events = Event.where(key_name.to_sym.in => key_array , :eventStatus => 'OPEN')
                                        @match_events = evaluator.get_matching_objects(existing_open_events)
                                        if !  @match_events.blank?
                                                # UNSTAGE if required
                                                logger.debug("Events ------ exists")
                                                matched_ids = @match_events.pluck("_id")
                                                logger.debug("  #{matched_ids}  ")
                                                Event.where(:id.in =>  @match_events).update_all(:isStage => false)
                                                return event
                                        else
                                                logger.debug("  PARM KEY VALUE MATCHED , setting stage ")
                                                event['isStage'] = true
                                                event['stageDuration'] = DateTime.strptime(event['firstTime'], '%Y-%m-%d %H:%M:%S').utc.to_time.to_i + key_hash[event[key_name]].to_i
                                                return event
                                        end
                                else
                                        logger.debug("Events  NOT  exists")
                                        # check factors
                                        if key_array.include?(event[key_name])
                                                #match found
                                                logger.debug("  PARM KEY VALUE MATCHED , setting stage ")
                                                event['isStage'] = true
                                                event['stageDuration'] = DateTime.strptime(event['firstTime'], '%Y-%m-%d %H:%M:%S').utc.to_time.to_i + key_hash[event[key_name]].to_i
                                                return event
                                        else
                                                return event
                                        end
                                end
                        end
                end
                return event
        end

        def manualnew
                @event = Event.new
        end

        def manualcreate
                Time.zone = current_user.time_zone if user_signed_in?
                event = Event.new(event_params)
                event.set(:eventStatus => "OPEN",:manualParent => true, :alertSummary => "Grouped Alert for pattern #{event.entity}", :eventID => "grouped-#{event.entity}")
                if event.save
                        event.worklogs.create(:user => current_user.login, :comment => "Parent event created")
                        respond_to do |format|
                                format.html { redirect_to events_url, info: 'Parent event was successfully created.' }
                        end
                end
        end

        # POST /events.json
        def create
                @noc_eventgroups = ["it-NOC-portaladmin","IT-NOC-PORTALADMIN@alertman.com","resilience@alertman.com","noc-investigation@alertman.com","IT-NOC-Middleware@alertman.com","it-NOC-middlewareadmin","it-NOC-linux@alertman.com","NOC-SMART@alertman.com","Clearpass Team","NOC-smart@alertman.com","it-NOC-linux@alertman.com","it-NOC-monitoring@alertman.com","it-NOC-monitoring@alertman.com","vC3","NOCnetwork@alertman.com","IT-NOC-oracle@alertman.com","dbaas-team@alertman.com","it-NOC-oracle@alertman.com","Noc-Oracle DBA","dbaas-team","Noc-Cloudops@alertman.com","Decc-L1-Support@alertman.com"]
                Time.zone = 'UTC'
                respond_to do |format|
                        ### Validation of alert data
                        required_keys = [
                                'entity',
                                'firstTime',
                                'eventSource',
                                'serviceName',
                                'alertSummary',
                                'severity',
                                'eventType',
                                'eventID',
                                ]
                        required_keys.each do |key|
                                if (! params['event'][key].present?) or (params['event'][key].blank?)
                                        #reject the event
                                        return render :json => {"error":true , "message": "param #{key} not found or empty"},  status: :bad_request
                                end
                                if (! params['event']['eventType'] == 'CREATE') or (! params['event']['eventType'] == 'CLEAR')
                                        return render :json => {"error":true , "message": "eventType should be either 'CREATE' or 'CLEAR'. provided #{params['event']['eventType']}."},  status: :bad_request
                                end
                                if ! valid_date?(params['event']['firstTime'])
                                        return render :json => {"error":true , "message": "invalid firstTime date: Expected date format is yyyy-mm-dd hh:mm:ss"} , status: :bad_request
                                end
                                if (params['event']['lastTime'].present?) and (! valid_date?(params['event']['lastTime']))
                                        return render :json => {"error":true , "message": "invalid lastTime date: Expected date format is yyyy-mm-dd hh:mm:ss"} , status: :bad_request
                                end
                                if ! valid_date?(params['event']['firstTime'])
                                        return render :json => {"error":true , "message": "invalid date: date format is yyyy-mm-dd hh:mm:ss"} , status: :bad_request
                                end
                end
                ### params not to be pushed to eTags
                exclude_etags = [
                        'firstTime',
                        'severity',
                        'eventID',
                        'eventType',
                        'eventStatus',
                        'lastTime',
                        'alertSummary',
                        'alertNotes',
                        'ipAddress',
                        'eventGroups'
                ]
                          if params['event']['eventType'] == 'CREATE'
                                # check flap detection
                                if check_event_flap(params['event']) == 1
                                                 render(:json => { :status => "flapping detected" }) and return
                                                 return
                                end

                                #check for existing event
                                existing_event = Event.where(eventStatus: { '$in': ['OPEN'] } , :eventID => params['event']['eventID'])
                        if existing_event.count > 0
                                        logger.debug("Existing EVENT : "+ params['event']['eventID'])
                                        event = existing_event.first
                                        event.update(:eventCount => event['eventCount'].nil? ? 1 : event['eventCount'] +  1, :lastTime => Time.now.utc, :alertSummary => params['event']['alertSummary'], :alertNotes => params['event']['alertNotes'], :eventGroups => params['event']['eventGroups'])
                                        format.json { render json: '"status": "updated"' }
                                else
                                        logger.debug("NEW EVENT : "+ params['event']['eventID'])
                                        event_params1 = check_corel(event_params)
                                        event = Event.new(event_params1)
                                        if event.save
                                                addAdditionalTags(event,exclude_etags)
                                                setEtags(event)
                                                dropped,bl_name,event = blackedout?(event)
                                                if dropped == 0
                                                        processpriorityrules(event)
                                                        processrules(event)
                                                        @noc_eventgroups.each do |eg|
                                                                if event.eventGroups.downcase.include? eg.downcase
                                                                        event.add_to_set(tags: "NOC-ALERT")
                                                                end
                                                        end
                                                        appendAlertNotes = ''
                                                        similarEventsCount = Event.where(:firstTime.gte => ( event['firstTime'].utc - 24.hours), :entity => event['entity'], :serviceName => event['serviceName'], :severity => event['severity']).count
                                                        if similarEventsCount > 1
                                                                appendAlertNotes = "<br><br> This alert appeared #{similarEventsCount} times in last 24 hours"
                                                        end
                                                        event.update(:eventCount => event['eventCount'].nil? ? 1 : event['eventCount'] +  1, :lastTime => event[:firstTime] , :alertNotes => event['alertNotes'] + appendAlertNotes , :eaNode => AppConstants::ALERTMAN_HOST )
                                                        processIncident(event)
                                                        processBpincident(event)
                                                        processNotifications(event)
                                                        processautohealrules(event)
                                                        format.html { redirect_to event, notice: 'Event was successfully created.' }
                                                        format.json {
                                                                @event = event
                                                                render :show, status: :created, location: event
                                                        }
                                                else ### else of dropped
                                                        event.update(:eventCount => event['eventCount'].nil? ? 1 : event['eventCount'] +  1, :lastTime => event[:firstTime], :eaNode => AppConstants::ALERTMAN_HOST)
                                                        event.worklogs.create(:user => 'System', :comment => "Event suppressionout by suppression Window #{bl_name}.")
                                                        format.json { render json: '"status": "dropped"' and return}
                                                end
                                        else
                                                format.html { render :new }
                                                 format.json { render json: event.errors, status: :unprocessable_entity }
                                        end
                                end ## end of new
                        else ## else of create
                                ## Clear alert
                                events = Event.where(:eventID => params['event']['eventID'], :eventStatus.ne => 'CLEARED')
                                if events
                                        logger.debug("  events to clear found  ")
                                        events.each do |event|
                                                clearEvent(event)
                                        end
                                else
                                        logger.debug("  events to clear NOT found  ")
                                end
                                format.html { redirect_to event, notice: 'Event was successfully created.' }
                                format.json { render json: '"status": "cleared"' }
                        end
                end
        end

        ## User Actions
        def action
                respond_to do |format|
                        event_length = params['data_value'].nil? ? 0 : params['data_value'].length
                        if params['data_value'].nil?
                                        format.json { render :json =>  {:status => "error", :message  =>  "No events selected" } }
                        elsif params['eaction'] == 'acknowledge' and ! params['data_value'].nil?
                                params['data_value'].each do | event |
                                        eventObj = Event.find(event)
                                        if eventObj['ackTime'].nil?
                                                eventObj.update(:ackTime => Time.now, :ackUser => current_user.login )
                                        end
                                        eventObj.update(:eAck => 'YES')
                                        eventObj.worklogs.create(:user => current_user.login, :comment => "Event Acknowledged")
                                        # If grouped alert, acknowledge child alerts as well.
                                        if ! eventObj.ihash.nil?
                                                # Get the individual alerts
                                                eventObj.groupevents.each do |gevent|
                                                        iEvent = Event.find(gevent)
                                                        if iEvent['ackTime'].nil?
                                                                iEvent.update(:ackTime => Time.now, :ackUser => current_user.login )
                                                        end
                                                        iEvent.update(:eAck => 'YES')
                                                        iEvent.worklogs.create(:user => current_user.login, :comment => "Event Acknowledged from parent event")
                                                end
                                        end
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{event_length.to_s} events acknowledged" } }
                        elsif params['eaction'] == 'unacknowledge' and ! params['data_value'].nil?
                                params['data_value'].each do | event |
                                        eventObj = Event.find(event)
                                        eventObj.update(:eAck => 'NO',:ackTime => nil)
                                        eventObj.worklogs.create(:user => current_user.login, :comment => "Event Unacknowledged")
                                        if ! eventObj.ihash.nil?
                                                # Get the individual alerts
                                                eventObj.groupevents.each do |gevent|
                                                        iEvent = Event.find(gevent)
                                                        if iEvent['ackTime'].nil?
                                                                iEvent.update(:ackTime => Time.now, :ackUser => current_user.login )
                                                        end
                                                        iEvent.update(:eAck => 'NO')
                                                        iEvent.worklogs.create(:user => current_user.login, :comment => "Event Unacknowledged from parent event")
                                                end
                                        end
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{params['data_value'].length.to_i} events unacknowledged" } }
                        elsif params['eaction'] == 'follow' and ! params['data_value'].nil?
                                params['data_value'].each do | event |
                                        eventObj = Event.find(event)
                                        eventObj.update(:followup => 'YES')
                                        eventObj.worklogs.create(:user => current_user.login, :comment => "Event marked for followup")
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{event_length.to_s} events marked for followup" } }
                        elsif params['eaction'] == 'unfollow' and ! params['data_value'].nil?
                                params['data_value'].each do | event |
                                        eventObj = Event.find(event)
                                        eventObj.update(:followup => 'NO')
                                        eventObj.worklogs.create(:user => current_user.login, :comment => "Event followup flag removed")
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{event_length.to_s} events removed for followup" } }
                        elsif params['eaction'] == 'clear' and ! params['data_value'].nil?
                                params['data_value'].each do | event_string |
                                        event = Event.find(event_string)
                                        clearEvent(event)
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{event_length.to_s} events cleared"  } }
                        elsif params['eaction'] == 'feedback' and ! params['data_value'].nil?
                                params['data_value'].each do | event_string |
                                        event = Event.find(event_string)
                                        event.update(:priority => params['feedback'])
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{event_length.to_s} events priority feedback provided"  } }
                        elsif params['eaction'] == 'parentevent' and ! params['data_value'].nil?
                                child_events = []
                                parentevent = Event.find(params['parentevent'])
                                skip_counter = 0
                                params['data_value'].each do | event_string |
                                        event = Event.find(event_string)
                                        ## Logic for moving the events as child.
                                        # check if the event is a manual parent event and if yes, skip
                                        next if event.manualParent
                                        ## Skip the grouped alerts with cleared state.
                                        if (event['alertSummary'].include?('Grouped Alert for pattern') && event.eventStatus ==  "CLEARED")
                                                skip_counter += 1
                                                next
                                        end

                                        # Check if event is a grouped event.

                                        if event['alertSummary'].include?('Grouped Alert for pattern')  ## grouped
                                                logger.debug('parent event')
                                                if ! event.groupevents.nil?
                                                        logger.debug("****** Length ******* #{event.groupevents.length}")
                                                        childe = event.groupevents[0 .. -1]
                                                        logger.debug("Events to detach #{childe}")
                                                        childe.each do |childevent|
                                                                logger.debug("Detatching Event #{childevent}")
                                                                logger.debug("Size before pull  #{childe.length}")
                                                                event.with_lock do
                                                                        event.pull(groupevents: childevent)
                                                                        event.save!
                                                                end
                                                                logger.debug("Size after pull  #{childe.length}")
                                                                Event.find(childevent).update(:incId => parentevent.id)
                                                                event.worklogs.create(:user => current_user.login, :comment => "Detaching event")
                                                                child_events.push(childevent)
                                                                logger.debug("**** end detach -  #{childe.length}")
                                                        end
                                                        logger.debug("Array size after loop #{childe.length}")
                                                        ## disabling/hiding the current parent event with grouped flag
                                                        event.worklogs.create(:user => current_user.login, :comment => "Disabling event as child events moved to #{parentevent.id}")
                                                        event.update(:grouped => 1)
                                                end
                                        else # individual event
                                                logger.debug("This is individual event")
                                                event.update(:incId => parentevent.id, :grouped => 1)
                                                child_events.push(event.id)
                                        end
                                end
                                logger.debug("The new parents child events are  #{child_events}")
                                identifier = parentevent.entity
                                existing_childs = parentevent.groupevents.nil? ? [] : parentevent.groupevents
                                parentevent.update(:groupevents => existing_childs + child_events,:ihash => identifier) ## Need to take care of existing childs
                                c = 0
                                child_events.each do |ce|
                                        c += 1
                                        logger.debug("Attaching Event #{c.to_s}")
                                        Event.find(ce).worklogs .create(:user => current_user.login, :comment => "Attaching event to parent #{parentevent.id}")
                                        parentevent.worklogs.create(:user => current_user.login, :comment => "Attached event #{ce}")
                                end
                                movedeventscount = event_length - skip_counter
                                mesg = "#{movedeventscount.to_s} events moved to manual parent."
                                if skip_counter != 0
                                        mesg += "Skipped #{skip_counter} grouped alert as it is already cleared."
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  mesg  } }
                        elsif params['eaction'] == 'comment' and ! params['data_value'].nil?
                                params['data_value'].each do | event_string |
                                        event = Event.find(event_string)
                                        event.worklogs.create(:user => current_user.login, :comment => params['worklog'])
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{event_length.to_s} events commented"  } }
                        elsif params['eaction'] == 'email' and ! params['data_value'].nil?
                                sendSingleEmail(params['data_value'],params['to_emailid'],params['cc_emailid'],params['email_subject'],params['email_body'])
                                params['data_value'].each do | event_string |
                                        event = Event.find(event_string)
                                        event.worklogs.create(:user => current_user.login, :comment => "Email Notification sent to #{params['to_emailid']} , #{params['cc_emailid']}")
                                        if params['email_ack'] == 'on'
                                                if event['ackTime'].nil?
                                                event.update(:ackTime => Time.now, :ackUser => current_user.login, :eAck => 'YES' )
                                                event.worklogs.create(:user => current_user.login, :comment => "Event Acknowledged")
                                                end
                                        end
                                end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{event_length.to_s} events commented"  } }
                        elsif params['eaction'] == 'download' and ! params['filter'].nil?
                                logger.debug("^^^^^^^^^^^^^^^^^^^ #{params['filter']} ^^^^^^^^^^^^^^^ ")
                                events = downloadCsv(params['filter'])
                                format.json { send_data events , :filename => 'event_report.csv', :type => 'text/csv' }
                        elsif params['eaction'] == 'ticket'
                                params['data_value'].each do | event_string |
                                        event = Event.find(event_string)
                                        if params['ack'] == 'on'
                                                if event['ackTime'].nil?
                                                        event.update(:ackTime => Time.now, :ackUser => current_user.login, :eAck => 'YES' )
                                                        event.worklogs.create(:user => current_user.login, :comment => "Event Acknowledged")
                                                end
                                        end
                                        if ! params['jsd'].blank?
                                                event.update(:jsdticketNumber => params['jsd'], :ticketStatus => 'YES')
                                                event.worklogs.create(:user => current_user.login, :comment => "JSD Ticket number #{params['jsd']} updated")
                                        end
                                        if ! params['hnp'].blank?
                                                event.update(:hnpticketNumber => params['hnp'], :ticketStatus => 'YES')
                                                event.worklogs.create(:user => current_user.login, :comment => "HNP Ticket number #{params['hnp']} updated")
                                        end
                                        if ! params['worklog'].blank?
                                                event.worklogs.create(:user => current_user.login, :comment => params['worklog'])
                                        end
                                        if params['drop'] == 'on'
                                                event.update(:eventStatus => 'CLEARED', :suppressionName => "Manual Drop : " + params['suppression_name'], :dropped => "YES", :clearedTime => Time.now.utc )
                                                        event.worklogs.create(:user => current_user.login, :comment => "Event Dropped by user : #{params['suppression_name']} ")
                                                        event.worklogs.create(:user => current_user.login, :comment => "Event cleared as it is dropped manually ")
                                                        if ! event.groupevents.nil?
                                                                event.groupevents.each do |gevent|
                                                                        iEvent = Event.find(gevent)
                                                                        iEvent.update(:eventStatus => 'CLEARED', :suppressionName => "Manual Drop : " + params['suppression_name'], :dropped => "YES" , :clearedTime => Time.now.utc)
                                                                        iEvent.worklogs.create(:user => current_user.login, :comment => "Event Dropped by user : #{params['suppression_name']}")
                                                                        iEvent.worklogs.create(:user => current_user.login, :comment => "Event cleared as it is dropped manually ")
                                                                end
                                                        end
                                                end
                                        end
                                format.json { render :json =>  {:status => "ok", :message  =>  "#{event_length.to_s} events ticket information updated"  } }
                        else
                                format.json { render :json =>  {:status => "error", :message  =>  "Unknown action ${params['eaction']}" } }
                        end
                end
        end

        def createjsdticket(eventid = nil,ruleName = nil , project = nil , parameters = nil)
                logger.debug ("Event ID : #{eventid}")
                logger.debug(" Rule: #{ruleName}")
                logger.debug(" Project: #{project}")
                logger.debug(" Parameters: #{parameters}")
                if eventid.nil?
                        event = Event.find(params['eventid'])
                else
                        event = Event.find(eventid)
                end
                if project.nil?
                        project= params['project']
                end
                if parameters.nil?
                        parameters= params['parameters']
                end
                # Check if ticket creation is already under processing
                createjsdticket = 0
                if ! event.jsdticketNumber.blank?
                        createjsdticket = 0
                elsif event.jsdStatus.nil?
                        #Ticket Not created
                        createjsdticket = 1
                elsif (( Time.now() - event.jsdStatus ).to_i > 120)
                        createjsdticket = 1
                end

                # For auto Generated  tickets
                if current_user.nil?
                        repuser = 'AlertMan System'
                else
                        repuser = current_user.login
                end

                if createjsdticket == 1
                        event.update(:jsdStatus => Time.now())
                        require 'net/http'
                        require 'uri'
                        require 'json'
                        hostname = Socket.gethostname
                        uri = URI.parse(AppConstants::JSD_API_URI)
                        request = Net::HTTP::Post.new(uri)
                        request.basic_auth AppConstants::JSD_BASIC_AUTH_USER, AppConstants::JSD_BASIC_AUTH_PASS
                        request.content_type = "application/json"
                        ### Prepare Markdown
                        payload = Jsddetail.where(:projectName => project)[0]['payload']
                        md = prepareMarkdown(event,project,payload,ruleName,parameters)
                        logger.debug("Markdown prepared #{md}")
                        parsed = JSON.parse(md)
                        if parsed['fields']['priority']['name'] == "Default"
                                logger.debug("Priority is default")
                                # Do the priority mapping table check.
                                if ['P0','P1','P2','P3','P4'].include?(event['eventPriority']) ## Event has priority. find and use the priority from mappy table.
                                        logger.debug("ALERT MAN has priority set as #{event['eventPriority']}")
                                        priority = Prioritymapping.where(:project => project , :eapriority => event['eventPriority'] ).first
                                        parsed['fields']['priority']['name'] = priority['projectpriority']
                                else
                                        logger.debug("ALERT MAN has no set priority :  #{event['eventPriority']}")
                                        priority = Prioritymapping.where(:project => project , :eapriority => "Default" ).first
                                        parsed['fields']['priority']['name'] = priority['projectpriority']
                                end
                        end
                        md = parsed.to_json
                        request.body = md
                        logger.debug("Request Body is ********** #{request.body}")
                        request["Cache-Control"] = "no-cache"
                        req_options = {
                                use_ssl: uri.scheme == "https",
                        }
                        begin
                                response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
                                        http.request(request)
                                end
                                logger.info("JSD Ticket creation API response : #{response.body}")
                                @response = response.body
                                resp = JSON.parse(@response)
                                if resp.key?("key")
                                        @tkt = resp["key"]
                                        event.update(:jsdticketNumber => resp['key'] , :ticketStatus => 'YES')
                                        event.push(tickets: resp['key'])
                                        event.worklogs.create(:user => repuser, :comment => "Ticket " + resp['key'] + " created")
                                        if ! (ActionController::Base.helpers.strip_tags(event.alertNotes) == event.alertNotes)
                                                logger.info("Require Attachment")
                                                event.alertNotes = event.alertNotes.gsub('"','\"')
                                                `echo "#{event.alertNotes}" > /tmp/#{resp['key']}.html`
                                                `curl -D- -u #{AppConstants::JSD_CREDENTAILS} -X POST -H "X-Atlassian-Token: nocheck" -F "file=@/tmp/#{resp['key']}.html" https://#{AppConstants::JSD_HOSTNAME}/rest/api/2/issue/#{resp['key']}/attachments`
                                        end
                                        if ! event.ihash.nil?
                                                # Get the individual alerts
                                                event.groupevents.each do |gevent|
                                                        iEvent = Event.find(gevent)
                                                        if iEvent['jsdticketNumber'].nil?
                                                                iEvent.update(:jsdticketNumber => resp['key'] )
                                                        end
                                                        iEvent.update(:eAck => 'YES')
                                                        iEvent.worklogs.create(:user => repuser, :comment => "Assigned TKT #{event['jsdticketNumber']}")
                                                end
                                        end
                                        if ! current_user.nil?
                                                render :json =>  {:status => "OK", :ticket  =>  resp['key'] }
                                        end
                                else
                                        if ! current_user.nil?
                                                render :json =>  {:status => "WARN", :message  => "Ticket Number not received #{resp['errorMessages'].to_s}" }
                                        end
                                end
                        rescue StandardError => e
                                logger.debug("Error creating Ticket : #{e.message} ")
                                if ! current_user.nil?
                                        render :json =>  {:status => "ERROR", :ticket  => "Error : #{e.message}"  }
                                end
                        end
                else
                        if ! current_user.nil?
                                render :json =>  {:status => "WARN", :message  =>  "Ticket already created or in progress. please try after 1 minute." }
                        end
                end
        end

        def ackAlert(eventid  = nil)
                if eventid.nil?
                        event = Event.find(params['eventid'])
                else
                        event = Event.find(eventid)
                end

                if current_user.nil?
                        repuser = 'AlertMan System'
                else
                        repuser = current_user.login
                end

                if event['ackTime'].nil?
                        event.update(:ackTime => Time.now, :ackUser => repuser , :eAck => 'YES' )
                        event.worklogs.create(:user => repuser , :comment => "Event Acknowledged")
                        if ! event.ihash.nil?
                                # Get the individual alerts
                                logger.debug("In Ack ")
                                event.groupevents.each do |gevent|
                                        iEvent = Event.find(gevent)
                                        if iEvent['ackTime'].nil?
                                                iEvent.update(:ackTime => Time.now, :ackUser => repuser )
                                        end
                                        iEvent.update(:eAck => 'YES')
                                        iEvent.worklogs.create(:user => repuser, :comment => "Event Acknowledged")
                                end
                        end
                        if ! current_user.nil?
                                render :json =>  {:status => "OK"}
                        end
                        # If grouped alert, acknowledge child alerts as well.
                else
                        if ! current_user.nil?
                                render :json =>  {:status => "Already Acknowledged"}
                        end
                end
        end

        def createhnpticket(eventid = nil,ruleName = nil , hnp_group = nil , hnp_priority = nil)

                if eventid.nil?
                        event = Event.find(params['eventid'])
                else
                        event = Event.find(eventid)
                end

                if hnp_group.nil?
                        hnp_group = AppConstants::CO_DEFAULT_HN_GROUP
                end

                if hnp_priority.nil?
                        hnp_priority = AppConstants::CO_DEFAULT_HN_PRIORITY
                end

                logger.debug("  #{hnp_group}  ")
        # Check if ticket creation is already under processing
        createhnpticket = 0
        if ! event.hnpticketNumber.blank?
            createhnpticket = 0
        elsif event.hnpStatus.nil?
            #Ticket Not created
            createhnpticket = 1
        elsif (( Time.now() - event.hnpStatus ).to_i > 120)
            createhnpticket = 1
        end

                if createhnpticket == 1
                        begin
                                event.update(:hnpStatus => Time.now())
                                require "uri"
                                require "net/http"

                                url = URI(AppConstants::CO_TICKETS_URL)
                                https = Net::HTTP.new(url.host, url.port)
                                https.use_ssl = true

                                request = Net::HTTP::Post.new(url)
                                request["Content-Type"] = "application/json"
                                request["csp-auth-token"] = System.first.clearOceantoken

                                # For auto Generated  tickets
                                if current_user.nil?
                                        repuser = 'AlertMan System'
                                else
                                        repuser = current_user.login
                                end
                                # Get event details
                                event_details = "Entity : #{event.entity}\n
                                        IP Addess : #{event.ipAddress}\n
                                        Service name : #{event.serviceName}\n
                                        Alert Summary : #{event.alertSummary}\n
                                        Severity : #{event.severity}\n
                                        First Occurance :  #{event.firstTime.utc}\n
                                        Event Source : #{event.eventSource}\n
                                        Event Groups : #{event.eventGroups}\n
                                        Event ID : #{event.eventID}\n
                                        Alert Notes : #{event.alertNotes}\n
                                        ALERT MAN LinkBack : <a target=\"_blank\" href=\"https://ea.alertman.com/events/#{event.id}\">ALERT MAN Link</a>\n
                                        Reported by : #{repuser}\n"
                                logger.debug ("Orule is  #{ruleName} ")
                                if ! ruleName.nil?
                                        event_details += "\nNotification Rule Name : #{ruleName} \n"
                                end
                                if hnp_priority == "Default"
                                        if ['P0','P1','P2','P3','P4'].include?(event['eventPriority']) ## Event has priority. find and use the priority from mappy table.
                                                logger.debug("ALERT MAN has priority set as #{event['eventPriority']}")
                                                priority = Prioritymapping.where(:project => 'HNP' , :eapriority => event['eventPriority'] ).first
                                                hnp_priority = priority['projectpriority']
                                        else
                                                logger.debug("ALERT MAN has no set priority :  #{event['eventPriority']}")
                                                priority = Prioritymapping.where(:project => 'HNP' , :eapriority => "Default" ).first
                                                hnp_priority = priority['projectpriority']
                                        end
                                end
                                request.body =JSON.dump({"service":{"id":"#{AppConstants::CO_DEFAULT_SERVICE_ID}"},"description": event_details,"requestedFor":{"userName":"#{AppConstants::CO_USER}"},"assignmentGroup":{"id": hnp_group}, "priority":{"id": hnp_priority}})
                                logger.info("TicketCreate Request Body -- " + request.body)
                                response = https.request(request)
                                logger.info("TicketCreate Response Body DEBUG1-- " + response.body)
                                @response = response.body
                                if @response.include? 'TKT'
                                        t_num = JSON.parse(@response)
                                        @tkt = t_num["id"]
                                        event.update(:hnpticketNumber => t_num["id"] , :ticketStatus => 'YES')
                                        event.push(tickets: t_num["id"])
                                        event.worklogs.create(:user => repuser, :comment => "Ticket " + t_num["id"] + " created")
                                        # If grouped alert, acknowledge child alerts as well.
                                        if ! event.ihash.nil?
                                                # Get the individual alerts
                                                event.groupevents.each do |gevent|
                                                        iEvent = Event.find(gevent)
                                                        if iEvent['hnpticketNumber'].nil?
                                                                iEvent.update(:hnpticketNumber => event['hnpticketNumber'] )
                                                        end
                                                        iEvent.update(:eAck => 'YES')
                                                        iEvent.worklogs.create(:user => repuser, :comment => "Assigned TKT #{event['hnpticketNumber']}")
                                                end
                                        end
                                        if ! current_user.nil?
                                                render :json =>  {:status => "OK", :ticket  =>  t_num["id"] }
                                        end
                                else
                                        event.worklogs.create(:user => "AlertMan System", :comment => "Error creating CO Ticket - API response #{response.body}")
                                        if ! current_user.nil?
                                                render :json =>  {:status => "ERROR", :ticket  =>  response.body }
                                        end
                                end
                        rescue => e
                                event.worklogs.create(:user => "AlertMan System", :comment => "CO Ticket Failed  :#{e.message}")
                                logger.debug("Clear Ocean Failed #{e.message}")
                        end
                end
        end

        def check_existing_ticket(event,reuseTime)
                existing_hnp_ticket = Event.where(entity: event['entity'], serviceName: event['serviceName'], :firstTime.gte => ( event['firstTime'].utc - 4.hours), :hnpticketNumber.nin => ["", nil])
                found = existing_hnp_ticket.count
                logger.debug ("- #{found} ")
                if found != 0
                        if reuseTime.nil?
                                look_back_minutes = 240
                        else
                                look_back_minutes = reuseTime
                        end
                        # check if there are events before the window start time.
                        events_before_window = Event.where(entity: event['entity'], serviceName: event['serviceName'], :firstTime.lte => ( event['firstTime'].utc - look_back_minutes.minutes), :hnpticketNumber => existing_hnp_ticket.last['hnpticketNumber']).count
                        if events_before_window != 0 # There are events before x hours window. This should create new ticket
                                return 0 ,''
                        end
                        return found , existing_hnp_ticket.last['hnpticketNumber']
                else
                        return found ,''
                end
        end

        def check_existing_jsd_ticket(event,reuseTime)
                existing_jsd_ticket = Event.where(entity: event['entity'], serviceName: event['serviceName'], :firstTime.gte => ( event['firstTime'].utc - 4.hours), :jsdticketNumber.nin => ["", nil])
                found = existing_jsd_ticket.count
                logger.debug (" #{found} ")
                if found != 0
                        if reuseTime.nil?
                                look_back_minutes = 240
                        else
                                look_back_minutes = reuseTime
                        end
                        # check if there are events before the window start time.
                        events_before_window = Event.where(entity: event['entity'], serviceName: event['serviceName'], :firstTime.lte => ( event['firstTime'].utc - look_back_minutes.minutes), :jsdticketNumber => existing_jsd_ticket.last['jsdticketNumber']).count
                        if events_before_window != 0 # There are events before x hours window. This should create new ticket in alertman
                                return 0 ,''
                        end
                        return found , existing_jsd_ticket.last['jsdticketNumber']
                else
                        return found ,''
                end
        end


        def downloadxlsx

                @filter1 = params['filter']
                respond_to do |format|
                        format.xlsx {
                                render xlsx: 'downloadxlsx', filename: "event_report_#{DateTime.now().strftime("%F_%T")}.xlsx"
                        }
                end
        end

        def downloadCsv(filter)

                logger.debug('In download method')
                mapping = {}
                mapping["1"] = 'firstTime'
                mapping["2"] = 'lastTime'
                mapping["3"] = 'clearedTime'
                mapping["4"] = 'entity'
                mapping["5"] = 'ipAddress'
                mapping["6"] = 'serviceName'
                mapping["7"] = 'severity'
                mapping["8"] = 'alertSummary'
                mapping["9"] = 'alertNotes'
                mapping["10"] = 'ticketStatus'
                mapping["11"] = 'jsdticketNumber'
                mapping["12"] = 'hnpticketNumber'
                mapping["13"] = 'eventSource'
                mapping["14"] = 'eventCount'
                mapping["15"] = 'eventStatus'
                mapping["16"] = 'eventID'
                mapping["17"] = 'tags'
                mapping["18"] = 'entityLocation'
                mapping["19"] = 'eAck'
                mapping["21"] = 'dropped'

                events = Event.where(:isStage.in => [false,nil],:grouped.in => [0,nil])
                filter = URI.decode(filter)
                filter = JSON.parse(filter)
                filter.keys.each do |col|
                        if filter[col].blank?
                                        logger.debug(col + ': filter is blank')
                        else
                                if filter[col].respond_to?(:keys)  ## This must be Datetime filter
                                        if filter[col]['from'].blank? and filter[col]['to'].blank?
                                                logger.debug(col + ': filter is blank')
                                        else
                                                if filter[col]['from'].blank?
                                                        filter[col]['from'] = '2019-01-01 00:00:00'
                                                end
                                                if filter[col]['to'].blank?
                                                        filter[col]['to'] = Time.now.utc
                                                end
                                                events = events.where("#{mapping[col]}".to_sym.gte => "#{filter[col]['from']}" , "#{mapping[col]}".to_sym.lte => "#{filter[col]['to']}")
                                                logger.debug(col + ': filter is NOT blank')
                                        end
                                elsif filter[col].kind_of?(Array) ## This must be eventSource
                                        events = events.where( :eventSource.in => filter[col]  )
                                elsif [true, false].include? filter[col] ## This must be "dropped"
                                        events = events.where( :dropped => filter[col]  )
                                else
                                        events = events.where("#{mapping[col]}" => /#{filter[col]}/i)
                                        logger.debug(col + ': filter is NOT blank ' + mapping[col])
                                end
                        end
                end
                events = events.order_by(firstTime: :desc)
                logger.debug(events.count.to_s)
                require 'csv'
                csv_string = CSV.generate(quote_char: '"', :force_quotes => true) do |csv|
                        csv << ["Entity","ipAddress","serviceName","severity","alertSummary","alertNotes","ticketStatus","jsdticketNumber","hnpticketNumber","eventSource","firstTime","lastTime","clearedTime","eventCount","eventStatus","eventID","eAck","tags","entityLocation","appName","eTags","ackUser","ackTime","Dropped","suppression ID","suppression Name","Parent Alert","OID"]
                        events.each do |e|
                                parent_alert = 0
                                if e.grouped.nil? || e.grouped == 0
                                        parent_alert = 1
                                end
                                e.alertNotes.gsub!('"','') ## temporary fix for quotes issue
                                e.alertNotes.gsub!(',','') ## temporary fix for quotes issue
                                e.alertNotes.gsub!(/^(.{50,}?).*$/m,'\1...') ## temporary fix for quotes issue

                                csv << ["#{e.entity}","#{e.ipAddress}","#{e.serviceName}","#{e.severity}","#{e.alertSummary}","#{e.alertNotes}","#{e.ticketStatus}","#{e.jsdticketNumber}","#{e.hnpticketNumber}","#{e.eventSource}","#{e.firstTime}","#{e.lastTime}","#{e.clearedTime}","#{e.eventCount}","#{e.eventStatus}","#{e.eventID}","#{e.eAck}","#{e.tags}","#{e.entityLocation}","#{e.appName}","#{e.eTags}","#{e.ackUser}","#{e.ackTime}","#{e.dropped}","#{e.suppressionId}","#{e.suppressionName}", parent_alert ,"#{e.id}"]
                        end
                end
                logger.debug("CSV  is " +  csv_string.to_s)
                return csv_string.to_s
        end

        def sanitizeS(string)
                string = string.nil? ? '' : string
                logger.debug ("String to sanitize " + string)
                pattern = /(\'|\"|\/|\\)/
                string = string.gsub(pattern){|match|"\\"  + match}
                logger.debug ("String sanitized " + string)
                return string
        end



        def prepareMarkdown(event,projectName,payload, ruleName, parameters)
                logger.debug("Payload : #{payload}")
                logger.debug("event : #{event}")
                logger.debug("Project : #{projectName}")
                logger.debug("rulename : #{ruleName}")

                ### Prepare Markdown
                md = ''
                md += "| Entity |#{sanitizeS(event.entity)} |\\n"
                md += "| Severity |#{sanitizeS(event.severity)} |\\n"
                md += "| Ip Address |#{sanitizeS(event.ipAddress)} |\\n"
                md += "| Alert Summary |#{sanitizeS(event.alertSummary)} |\\n"
                md += "| Event Source |#{sanitizeS(event.eventSource)} |\\n"
                md += "| First Time |#{sanitizeS(event.firstTime.utc.to_s)} |\\n"
                md += "| Event Id |#{sanitizeS(event.eventID)} |\\n"
                md += "[ALERT MAN Link](https://#{AppConstants::ALERTMAN_HOST.gsub('.alertman.com','')}.alertman.com/events/#{event.id})\\n"
                if ! ruleName.nil?
                        md += "| Notification Rule Name |#{sanitizeS(ruleName)} |\\n"
                end
                eventTime = event.firstTime.utc.strftime('%Y-%m-%dT%H:%M:%S.%L%z')
                logger.debug("MD is  #{md}")
                markdown = payload
                #Hack for ITSD eventTime
                dummyhash = {"ALERTMAN_summary" => sanitizeS(event.alertSummary).truncate(250) , "ea-notes" => md , "ALERTMAN_jsd_type" => projectName }
                if projectName == 'ITSD'
                        dummyhash["ALERTMAN_eventTime"] = event.firstTime.utc.strftime('%Y-%m-%dT%H:%M:%S.%L%z')
                end

                dummyhash = parameters.merge(dummyhash)
                dummyhash.each { |k, v| markdown[k] &&= v }
                return markdown
        end

        def preparePdMarkdown(event)
                ### Prepare Markdown
                md = ''
                md += "| Entity |#{sanitizeS(event.entity)} |\\n"
                md += "| Severity |#{sanitizeS(event.severity)} |\\n"
                md += "| Ip Address |#{sanitizeS(event.ipAddress)} |\\n"
                md += "| Alert Summary |#{sanitizeS(event.alertSummary)} |\\n"
                md += "| Event Source |#{sanitizeS(event.eventSource)} |\\n"
                md += "| First Time |#{sanitizeS(event.firstTime.utc.to_s)} |\\n"
                md += "| Event Id |#{sanitizeS(event.eventID)} |\\n"
                md += "[ALERT MAN Link]( https://#{AppConstants::ALERTMAN_HOST.gsub('.alertman.com','')}.alertman.com/events/#{event.id} )\\n"
                logger.debug("MD is  #{md}")
                return md
        end

        def blackedout?(event)
                @suppressions = suppression.where(disabled: { :$in => [nil,false] }).order('indexorder ASC')
                # suppression Rule Matching
                dropped = 0
                bl_name = ''
                tmp_event = event
                tmp_event['firstTime1'] = event['firstTime']
                tmp_event['firstTime2'] = event['firstTime']
                logger.debug(" #{tmp_event.attributes}")

                @suppressions.each do |suppression|
                        logger.debug( "Processing ............ #{suppression['name']}")
                        begin
                                evaluator = JqueryQueryBuilder::Evaluator.new(suppression['rule'])
                                @match_events = evaluator.get_matching_objects([tmp_event.attributes])
                                if @match_events.blank?
                                        logger.debug('suppression Rule '+ suppression['name'] + ' not matched')
                                else
                                        logger.debug( 'suppression Rule '+suppression['name'] + ' matched')
                                        event.set(:eventStatus => 'CLEARED', :suppressionId => suppression['id'], :suppressionName => suppression['name'], :dropped => "YES")
                                        dropped = 1
                                        bl_name = suppression['name']
                                        break
                                end
                        rescue => error
                                logger.error("Error processing suppression #{suppression['name']} -- #{error.message}")
                        end
                end
                return dropped,bl_name,event
        end

        def processautohealrules(event)
                event = Event.find(event.id)
                @autohealrules = Autoheal.where(:enabled => true).order('indexorder ASC')
                # Event Rule Matching
                logger.debug( "Original Event : " + event.attributes.to_s)
                @autohealrules.each do |autohealrule|
                logger.debug( "Processing Auto Heal  #{autohealrule['name']}")
                begin
                        evaluator = JqueryQueryBuilder::Evaluator.new(autohealrule['rule'])
                        @match_events = evaluator.get_matching_objects([event.attributes])
                        if @match_events.blank?
                                logger.debug('Rule '+ autohealrule['name'] + ' not matched')
                        else
                                logger.debug( 'Rule '+ autohealrule['name'] + ' matched')
                                event.worklogs.create(:user => "AlertMan System", :comment => "Triggering remediation workflow #{autohealrule['name']}")
                                ## Check if any param is set
                                require "uri"
                                require "net/http"

                                url = URI(autohealrule['stackStormurl'])

                                https = Net::HTTP.new(url.host, url.port)
                                https.use_ssl = true
                                https.verify_mode = OpenSSL::SSL::VERIFY_NONE


                                request = Net::HTTP::Post.new(url)
                                request["Content-Type"] = "application/json"
                                request["Authorization"] = "Bearer #{System.first['stackStormtoken']}"
                                                        stackStormparams = autohealrule['stackStormparams']
                                                        stackStormtemplate = ERB.new(stackStormparams)
                                                        substituted_stackStorm_params = stackStormtemplate.result(binding)
                                                        logger.debug("Substituted stackStormparms is :: #{substituted_stackStorm_params}")
                                r = JSON.parse(substituted_stackStorm_params)
                                co_tkt =       {
                                        "value" => {
                                        "string" => {
                                        "value" => event['hnpticketNumber']
                                        }
                                        },
                                        "type" => "string",
                                        "name" => "co_tkt",
                                        "scope" => "local"
                                }
                                co_ritm =       {
                                        "value" => {
                                        "string" => {
                                        "value" => event['coritm']
                                        }
                                        },
                                        "type" => "string",
                                        "name" => "co_ritm",
                                        "scope" => "local"
                                }
                                                        ah_rule_name =       {
                                        "value" => {
                                        "string" => {
                                        "value" => autohealrule['name']
                                        }
                                        },
                                        "type" => "string",
                                        "name" => "ah_rule_name",
                                        "scope" => "local"
                                }

                                r['parameters'].push(co_tkt)
                                r['parameters'].push(co_ritm)
                                r['parameters'].push(ah_rule_name)
                                request.body = r.to_json
                                logger.debug(" #{r.to_json}")
                                response = https.request(request)
                                logger.debug("stackStorm RESPONSE  #{response.read_body}")
                                response_obj = JSON.parse(response.read_body)
                                if ! response_obj.nil?
                                        if ! response_obj['id'].blank?
                                                response_obj.delete('id')
                                        end
                                        event.worklogs.create(:user => "AlertMan System", :comment => "Workflow response  #{response_obj.to_json}")
                                        logger.debug(response.read_body)

                                else
                                        event.worklogs.create(:user => "AlertMan System", :comment => "ERROR: Workflow response  #{response.read_body}")
                                        logger.debug(response.read_body)
                                end
                        end
                        rescue => error
                                logger.error(" !!!!! Error processing erule #{autohealrule['name']} -- #{error.message.gsub("\n",'---')}")
                                event.worklogs.create(:user => "AlertMan System", :comment => "ERROR:   #{error.message.gsub("\n",'---')}")
                        end
                end
        end


        def processrules(event)
                @erules = Erule.all.order('indexorder ASC')
                # Event Rule Matching
                logger.debug( "Original Event : " + event.attributes.to_s)
                @erules.each do |erule|
                        logger.debug( "Processing  #{erule['name']}")
                        begin
                                evaluator = JqueryQueryBuilder::Evaluator.new(erule['rule'])
                                @match_events = evaluator.get_matching_objects([event.attributes])
                                if @match_events.blank?
                                        logger.debug('Rule '+ erule['name'] + ' not matched')
                                else
                                        logger.debug( 'Rule '+ erule['name'] + ' matched')
                                        event.worklogs.create(:user => "AlertMan System", :comment => "Event Rule #{erule['name']} Matched")
                                        ## Check if any param is set
                                        if ! erule['setvalue'].blank?
                                                logger.debug('Setting ' + erule['set'] + ' to ' + erule['setvalue'])
                                                if ['appName'].include? (erule['set']) # Update the eTags with the new values for incidents processing
                                                        temp_hash =  Hash.new
                                                        temp_hash = event.eTags
                                                        temp_hash[erule['set']] = erule['setvalue']
                                                        event.update(erule['set'] => erule['setvalue'], "eTags" => temp_hash)
                                                        event.worklogs.create(:user => "AlertMan System", :comment => "Setting Application name to #{erule['setvalue']}")
                                                elsif ['alertNotes'].include? (erule['set'])
                                                        if erule['setvalue'].start_with?('---APPEND---')
                                                                event.update(erule['set'] => event[erule['set']] + erule['setvalue'].sub('---APPEND---','<br>'))
                                                                event.worklogs.create(:user => "AlertMan System", :comment => "Appending Alert Notes")
                                                        else
                                                                event.update(erule['set'] => erule['setvalue'])
                                                                event.worklogs.create(:user => "AlertMan System", :comment => "Changing alert notes")
                                                        end
                                                else
                                                        event.update(erule['set'] => erule['setvalue'])
                                                        event.worklogs.create(:user => "AlertMan System", :comment => "Setting #{erule['set']} as #{erule['setvalue']}")
                                                end
                                        end
                                        ## TAG Management
                                        # split the tag_string to array
                                        erule['eventtags'].split(',').each do |x|
                                                logger.debug("Adding tag #{x} ")
                                                event.add_to_set(tags: x)
                                                event.worklogs.create(:user => "AlertMan System", :comment => "Adding Tag #{erule['eventtags']}")
                                        end
                                end
                        rescue => error
                                logger.error(" Error processing erule #{erule['name']} -- #{error.message}")
                        end
                end
        end

        def processpriorityrules(event)
                @prules = Prule.all.order('indexorder ASC')
                # Priority Rule Matching
                logger.debug( "Original Event : " + event.attributes.to_s)
                @prules.each do |prule|
                        logger.debug( "Processing Priority #{prule['name']}")
                        begin
                                evaluator = JqueryQueryBuilder::Evaluator.new(prule['rule'])
                                @match_events = evaluator.get_matching_objects([event.attributes])
                                if @match_events.blank?
                                        logger.debug('Priority Rule '+ prule['name'] + ' not matched')
                                else
                                        logger.debug( 'Priority Rule '+ prule['name'] + ' matched')
                                        event.worklogs.create(:user => "AlertMan System", :comment => "Priority Rule #{prule['name']} Matched")
                                        ## Check if any param is set
                                        if ! prule['setvalue'].blank?
                                                logger.debug('Setting Priority ' + prule['set'] + ' to ' + prule['setvalue'])

                                                event.update(prule['set'] => prule['setvalue'])
                                                event.worklogs.create(:user => "AlertMan System", :comment => "Setting #{prule['set']} as #{prule['setvalue']}")

                                        end
                                end
                        rescue => error
                                logger.error(" Error processing prule #{prule['name']} -- #{error.message}")
                        end
                end
        end

        def processTagrules(event,eTagHash)
                logger.debug(" PROCESSING TAG RULE ")
                @trules = Tag.all.order('indexorder ASC')
                # Event Rule Matching
                logger.debug( "Original Event : " + event.attributes.to_s)
                @trules.each do |trule|
                        logger.debug( "Processing TAG Rule  #{trule['name']}")
                        begin
                                evaluator = JqueryQueryBuilder::Evaluator.new(trule['rule'])
                                @match_events = evaluator.get_matching_objects([event.attributes])
                                if @match_events.blank?
                                        logger.debug('TagRule '+ trule['name'] + ' not matched')
                                else
                                        logger.debug('TagRule '+ trule['name'] + ' matched')
                                        ## Check if any param is set
                                        if ! trule['valueassigned'].blank?
                                                eTagHash[trule['name']] = trule['valueassigned']
                                        elsif ! trule['regex'].blank?
                                                logger.debug('Extracting Regex ' + trule['regex'] + ' from ' + trule['field'])
                                                regex = trule['regex']
                                                string = event[trule['field']]
                                                logger.debug(" STRING is #{string}")
                                                code = 'string.scan(/'+regex+'/).last'
                                                extracted = eval(code)
                                                logger.debug  ("Extracted is #{extracted}")
                                                if extracted.kind_of?(Array)
                                                        if ! extracted.first.blank?
                                                                logger.debug("Extracted #{extracted.first} for #{trule['name']}")
                                                                eTagHash[trule['name']] = extracted.first
                                                                logger.debug("eTaghash: #{eTagHash}")
                                                        end
                                                end
                                        end
                                end
                        rescue => error
                                logger.error(" Error processing Tagrule #{trule['name']} -- #{error.message}")
                        end
                end
        end

        def enrichCMDB(event,etags)

                # Enrich Event with information from CMDB
                # check by IP
                logger.debug( "CMDB INFO : #{event['ipAddress']}")

                if IPAddress.valid_ipv4? event['ipAddress']
                        query = event['ipAddress']
                else
                        query = event['entity']
                end

                begin
                        event_enriched = 0
                        start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
                        require "uri"
                        require "net/http"
                        # check if element returned is not empty
                        url = URI("https://#{AppConstants::CMDB_HOST}/api/entity?data=#{query}")
                        https = Net::HTTP.new(url.host, url.port);
                        https.use_ssl = true
                        request = Net::HTTP::Get.new(url)
                        request["Content-Type"] = "application/x-www-form-urlencoded"
                        request["Accept"] = "application/json"
                        request["Authorization"] = "Api-Token #{AppConstants::CMDB_TOKEN}"
                        response = https.request(request)
                        logger.debug("monview response #{response.read_body}")

                        monview_ds = JSON.parse(response.read_body)
                        d = {}
                        if monview_ds[query] && monview_ds[query].length != 0
                                adcons = []
                                nonadcons = []

                                monview_ds[query].each do |o|
                                        logger.debug(" #{o} ")
                                                etags['appName'] = "UNKNOWN"
                                                etags['entityLocation'] = "UNKNOWN"
                                                etags['envName'] = ""
                                                etags['vCenter'] = ""
                                                etags['vCluster'] = ""
                                                if o['details'] && ! o['details']['application'].empty?
                                                        etags['appName'] = o['details']['application'][0]['name']
                                                        logger.debug("CMDB : #{o['details']['application'][0]['contacts']}")
                                                        if ! o['details']['application'][0]['contacts'].empty?
                                                                contacts =  o['details']['application'][0]['contacts']
                                                                adcons = []
                                                                nonadcons = []
                                                                contacts.each do |contact|
                                                                        if contact['type'] == 'AdPerson'
                                                                                adcons.push contact['mail']
                                                                        else
                                                                                nonadcons.push contact['mail']
                                                                        end
                                                                end
                                                        end
                                                end
                                                if o['details'] && o['details']['location'] && ! o['details']['location'].empty?
                                                        etags['entityLocation'] = o['details']['location'][0]
                                                end

                                                event_enriched = 1
                                                logger.debug(" #{d} ")
                                                break
                                end

                                # the current tagset
                                enriched = event.update(:appContacts => [], :appName => etags['appName'], :envName => "", :vCenter => "", :vCluster => "", :entityLocation => etags['entityLocation'], :eTags => etags )
                                logger.debug ("  eTags After : #{etags}")
                        end
                        if event_enriched == 1
                                logger.debug("Event Enriched from CMDB")
                        else
                                logger.debug("Event NOT Enriched from CMDB")
                        end
                        end_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
                        elapsed_time = end_time - start_time
                        logger.debug("The time taken for CMDB API call : #{event['eventID']} : #{event['ipAddress']} : #{elapsed_time}")
                rescue => e
                        logger.error ("unable to get response from CMDB. event will not be enriched -- #{e.message}")
                end
        end

        def processIncident(event)
                ## incident
                # check for the patterns. hard code it now
                logger.debug('################# PROCESSING ALERT INSIGHT INCIDENT ###############')
                if event['severity'] == 'CRITICAL'
                        patterns = ['appName','entityLocation','serviceName','eventSource']
                        # check if the incomming event has these tags
                        event_tags = event[:eTags]
                        logger.debug ("================= eTags Latest : #{event_tags}")
                        patterns.each do |indpattern|
                                logger.debug("Processing pattern #{indpattern}")
                                begin
                                        pattern_present = 1
                                        if ! event_tags.key?(indpattern)
                                                pattern_present = 0
                                        end
                                        if pattern_present == 1
                                                logger.debug( ' PATTERN PRESENT ###')
                                                # make the identifier of the pattern tags
                                                identifier = ''
                                                identifier = indpattern +'_'+ event_tags[indpattern]
                                                # check if the Incident with the same identifier is present
                                                logger.debug ( " Identifier is #{identifier}")
                                                ihash_existing = Incident.where(:ihash => identifier)
                                                if ihash_existing.count != 0 ## Identifier is present, add the event to the incident
                                                        @incident = ihash_existing.first.add_to_set(events: event['id'])
                                                        event.push(insightIncidentids: @incident.id)
                                                else ## Identifier is NOT present. create incident
                                                        logger.debug( " New Incident")
                                                        @incident = Incident.create(:name => 'Dummy',:ihash => identifier , :tags => [indpattern])
                                                        Incident.read(mode: :primary).find(@incident['id']).add_to_set(events: event['id'])
                                                        event.push(insightIncidentids: @incident.id)
                                                end
                                        end
                                rescue => error
                                        logger.error("!!!!! Error processing Pattern #{indpattern} -- #{error.message}")
                                end
                        end
                end
        end

        def processBpiincident(event)
                ## BP incident
                # check for the patterns. hard code it now
                # Get the pattern from etags model
                patterns = []
                Cpattern.all.each do |pattern|
                        dummy_hash = Hash.new
                        a = pattern['pattern']
                        a = a.reject { |element| element.empty? }
                        dummy_hash['name'] = pattern['name']
                        dummy_hash['tags'] = a
                        dummy_hash['duration'] = pattern['duration']
                        logger.debug("  Pushing pattern #{dummy_hash}")
                        patterns.push(dummy_hash)
                end
                # check if the incomming event has these tags
                logger.debug("PATTERNS is FIRST #{patterns.to_s}")
                patterns = patterns.sort_by {| element | element['duration']}
                # Add the entity based correlation at the end
                event_tags = event[:eTags]
                logger.debug("PATTERNS is #{patterns.to_s}")
                patterns.each do |indpattern|
                        pattern_present = 1
                        logger.debug(" Taking pattern #{indpattern['tags'].to_s} -- #{indpattern['duration'].to_s}")
                        indpattern['tags'].each do |pattern|
                                if ! event_tags.key?(pattern)
                                        pattern_present = 0
                                        break
                                end
                        end
                        if pattern_present == 1
                                logger.debug( ' Pattern Matched')
                                # make the identifier of the pattern tags
                                identifier = event['severity'] + '--'
                                indpattern['tags'].each do |pattern|
                                        identifier = identifier + event_tags[pattern]
                                end

                                # check if the Incident with the same identifier is present
                                logger.debug(" Identifier is #{identifier} ")
                                bpincident_existing = Event.where(:ihash => identifier,:eventStatus => "OPEN")

                                if bpincident_existing.count != 0 ## Identifier is present, check the duration
                                        logger.debug(" Identifier #{identifier} present")
                                        bpincident = bpincident_existing.last
                                        timediff = (event['firstTime'] - bpincident['firstTime']).to_i
                                        ### NOTE : below for testing #######
                                        if timediff <= indpattern['duration'].to_i # Incident present and active
                                                logger.debug(" Identifier #{identifier} is within duration -- #{timediff} :: #{indpattern['duration'].to_i}")
                                                bpincident.add_to_set(groupevents: event['id'])
                                                bpincident.worklogs.create(:user => "AlertMan System" , :comment => "Adding event <a target='_blank' href='/events/#{event.id}'> #{event.id}</a> to group")
                                                updateparams = {}
                                                bpupdateparams = {}
                                                bpupdateparams['lastTime'] = event['firstTime']
                                                if event['isStage'] == false
                                                        bpupdateparams['isStage'] = false
                                                end
                                                bpincident.update(bpupdateparams)
                                                ackAlert(event['id']) if bpincident['eAck'] == 'YES'

                                                if ! bpincident["hnpticketNumber"].blank?
                                                        updateparams["ticketStatus"] = 'YES'
                                                end
                                                if ! bpincident["jsdticketNumber"].blank?
                                                        updateparams["jsdticketNumber"] = bpincident["jsdticketNumber"]
                                                        updateparams["ticketStatus"] = 'YES'
                                                end
                                                updateparams['grouped'] = 1
                                                updateparams["incId"] = bpincident.id
                                                event.update(updateparams)

                                        else ### Incident is not active. create a new incident
                                                logger.debug("Identifier #{identifier} is NOT within duration.  -- #{timediff} :: #{indpattern['duration'].to_i}  - CREATE incident")
                                                # add the tags hash to incident for display. TODO : Make function
                                                taghash = Hash.new
                                                indpattern['tags'].each do |tag|
                                                        taghash[tag] = event['eTags'][tag]
                                                end
                                                bpincident = Event.create(:entity => event['entity'],:serviceName => event['serviceName'],:firstTime => event['firstTime'],:lastTime => event['firstTime'],:ihash => identifier , :duration => indpattern['duration'] ,:alertSummary => "Grouped Alert for pattern "+ indpattern['name'], :alertNotes => event['alertNotes'],:severity => event['severity'], :eventStatus => "OPEN", :groupevents => [event['id']],:eventID => "grouped-"+identifier, :eventSource => event['eventSource'],:eventGroups => event['eventGroups'], :isStage => event['isStage'] , :stageDuration => event['stageDuration'],:eventType => event['eventType'], :tags => event['tags'], :eventPriority => event['eventPriority'])
                                                bpincident.update(:alertNotes  => "<a href=\"https://#{AppConstants::ALERTMAN_HOST}/events/#{bpincident['id']}\" > Alert Details </a>")
                                                bpincident.worklogs.create(:user => "AlertMan System" , :comment => "Adding event <a target='_blank' href='/events/#{event.id}'> #{event.id}</a> to group")
                                                event.update(:grouped => 1 ,:incId => bpincident.id)
                                                processNotifications(bpincident)
                                                processautohealrules(bpincident)
                                        end
                                else ## Identifier is NOT present. create incident
                                        logger.debug(" Identifier #{identifier} NOT present. Create incident -- event['id']")
                                        # add the tags hash to incident for display. TODO : Make function
                                        taghash = Hash.new
                                        indpattern['tags'].each do |tag|
                                                taghash[tag] = event['eTags'][tag]
                                        end
                                        bpincident = Event.create(:entity => event['entity'],:serviceName => event['serviceName'],:firstTime => event['firstTime'],:lastTime => event['firstTime'],:ihash => identifier , :duration => indpattern['duration'] ,:alertSummary => "Grouped Alert for pattern "+ indpattern['name'] , :alertNotes => event['alertNotes'],:severity => event['severity'], :eventStatus => "OPEN", :groupevents => [event['id']],:eventID => "grouped-"+identifier,  :eventSource => event['eventSource'],:eventGroups => event['eventGroups'], :isStage => event['isStage'] , :stageDuration => event['stageDuration'],:eventType => event['eventType'], :tags => event['tags'], :eventPriority => event['eventPriority'])
                                        bpincident.update(:alertNotes  => "<a href=\"https://#{AppConstants::ALERTMAN_HOST}/events/#{bpincident['id']}\" > Alert Details </a>")
                                        bpincident.worklogs.create(:user => "AlertMan System" , :comment => "Adding event <a target='_blank' href='/events/#{event.id}'> #{event.id}</a> to group")
                                        event.update(:grouped => 1, :incId => bpincident.id)
                                        processNotifications(bpincident)
                                        processautohealrules(bpincident)
                                end
                                break
                        end
                end
        end

        def processNotifications(event)
                # check the alert rate for the Source.
                source = Source.where(:source => event['eventSource']).first
                # check if the source has alert snooze rate configured.
                begin
                        if ! source['snooze_limit'].nil? and ! source['snooze_window'].nil?
                                # check the events in the window.
                                logger.debug ('Notification snooze information found')
                                logger.debug("Snooze Limit: #{source['snooze_limit']} -- Snooze  Window : #{source['snooze_window']} ")
                                source_count = Event.where(:eventSource => event['eventSource'], :severity  => "CRITICAL" ,  :firstTime.gte => (Time.now.utc - source['snooze_window'].to_i.minutes)).count
                                logger.debug ("snooze -- real alert count is #{source_count}")
                                if source_count > source['snooze_limit'].to_i
                                        logger.debug("snooze event rate exceeded")
                                        return
                                end
                        end
                rescue => error
                        logger.error("Error - Notifications. Issue with Source #{source} -- #{error.message}")
                end

                # Notification Rule Matching
                @orules = Orule.all.order('indexorder ASC')
                logger.debug( "Original Event : " + event.attributes.to_s)
                ack = 0
                @orules.each do |orule|
                        logger.debug( " Notification Rule #{orule['name']}")
                        begin
                                evaluator = JqueryQueryBuilder::Evaluator.new(orule['rule'])
                                @match_events = evaluator.get_matching_objects([event.attributes])
                                if @match_events.blank?
                                        logger.debug( 'Rule '+ orule['name'] + ' not matched')
                                else
                                        logger.debug( 'Rule '+ orule['name'] + ' matched')
                                        # check if notification is to be delayed
                                        if orule['delay_notification'] == true
                                                event.worklogs.create(:user => "AlertMan System", :comment => "Delaying Notification rule #{orule['name']} by #{orule['delay_seconds']} seconds")
                                                logger.debug("------------------ Alert Man Notification delayed ---------------")
                                                DelayedNotification.perform_in(orule['delay_seconds'].seconds, event.id.to_s, orule.id.to_s)
                                                next
                                        else
                                                event.worklogs.create(:user => "AlertMan System", :comment => "Triggering Notification rule #{orule['name']} ")
                                                logger.debug( 'Sending Notification')

                                                if orule['hnp'] == true
                                                        # check if any hnp ticket was created for same Entity & Service Name 8 hours ago.
                                                        hnpCreatedCount,hnpCreatedTkt = check_existing_ticket(event,orule['hnp_reuse_time'])
                                                        if hnpCreatedCount.to_i == 0
                                                                createhnpticket(event['id'],orule['name'], orule['hnp_group'].blank? ? nil : orule['hnp_group'], orule['hnp_priority'].blank? ? nil : orule['hnp_priority'])
                                                                ack = 1
                                                        else
                                                                logger.debug(" Existing Ticket ")
                                                                event.push(tickets: hnpCreatedTkt)
                                                                event.update(:eAck => 'YES',:ackTime => Time.now, :ackUser => "System",hnpticketNumber: hnpCreatedTkt, :ticketStatus => 'YES')
                                                                event.worklogs.create(:user => "AlertMan System", :comment => "Using existing Ticket #{hnpCreatedTkt}")
                                                                event.worklogs.create(:user => "AlertMan System", :comment => "Event Acknowledged")
                                                        end
                                                end
                                                if orule['jsd'] == true
                                                        # check if any hnp ticket was created for same Entity & Service Name 8 hours ago.
                                                        jsdCreatedCount,jsdCreatedTkt = check_existing_jsd_ticket(event,orule['jsd_reuse_time'])
                                                        if jsdCreatedCount.to_i == 0
                                                                createjsdticket(eventid = event['id'], ruleName = orule['name'],project = orule['jsd_type'], parameters = orule['jsd_variables'])
                                                                ack = 1
                                                        else
                                                                logger.debug(" Existing Ticket ")
                                                                event.push(tickets: jsdCreatedTkt)
                                                                event.update(:eAck => 'YES',:ackTime => Time.now, :ackUser => "System",jsdticketNumber: jsdCreatedTkt, :ticketStatus => 'YES')
                                                                event.worklogs.create(:user => "AlertMan System", :comment => "Using existing Ticket #{jsdCreatedTkt}")
                                                                event.worklogs.create(:user => "AlertMan System", :comment => "Event Acknowledged")
                                                        end
                                                end
                                                if orule['email'] == true
                                                        emailFrom=orule['emailFrom'].nil? ? 'it-NOC-monitoring@alertman.com' : orule['emailFrom']
                                                        emailCC = orule['emailCC']
                                                        default_email_body = "
Hello,

Kindly look into the below alert.

Thanks,
NOC IT Team.
                                                                  "
                                                        emailTEXT = orule['emailCustombody'].nil? ? default_email_body : orule['emailCustombody']
                                                        emailTEXT += "

        [This email is triggered by Notification Rule:  #{orule['name']} ]
        "
                                                        sendAutoEmail(event[:id],orule['emailID'],emailFrom,emailCC,emailTEXT,orule['name'])
                                                        ack = 1
                                                end
                                                if orule['pd'] == true
                                                        sendPagerduty(event['id'],orule['pdS'],orule['pdEP'])
                                                        ack = 1
                                                end
                                                slacks = orule['slack']
                                                if ! slacks.nil?
                                                        slacks.each do |slack|
                                                                nslack = Slack.find(slack)
                                                                SlackWebhookWorker.perform_async(nslack['channel'],nslack['token'],event['id'])
                                                        end
                                                end
                                        end
                                end
                        rescue => error
                                logger.error(" !!!!! Error processing Notifiction #{orule['name']} -- #{error.message}")
                        end
                end
                ackAlert(event['id']) if ack ==  1
        end

        def setEtags(event)
                etags = event['eTags']
                logger.debug (" eTags Before : #{etags}")
                enrichCMDB(event,etags)
                ## Tagging for events not enriched from opsGPS
                ## Update the eTags set for form
                if Etag.first.nil?
                        Etag.create(:alltags => [])
                end
                Etag.read(mode: :primary).first.add_to_set({"alltags" => etags.keys })
        end

        def addAdditionalTags(event,exclude_etags)
                ## Adding dummy params for incident
                all_params =  params['event'].keys
                eTagHash = Hash.new
                all_params.each do |param|
                        if exclude_etags.include?(param)
                                next
                        else
                                eTagHash[param] = params['event'][param]
                        end
                end
                logger.debug("***** Going to add tag rule *******")
                processTagrules(event,eTagHash)
                logger.debug("eTaghash: #{eTagHash}")
                event.set('eTags' => eTagHash )
        end

        def valid_date?(datetime,format="%F %T")
                DateTime.strptime(datetime,format) rescue false
        end

        def clearEvent(event)
                logger.debug("Clear is #{event.to_json}")
                user = current_user.nil? ? 'System' : current_user.login
                ## Adding logic for changing severity to WARNING for staged events that cleared with in stage duration.

                if ( event['severity'] == 'CRITICAL' and  event['isStage'] == true and event['stageDuration'].to_i > Time.now.utc.to_i)
                        updated = event.update(:eventStatus => 'CLEARED', :clearedTime => Time.now.utc, :severity => 'WARNING')
                        event.worklogs.create(:user => user, :comment => "Changing severity to WARNING as event cleared within hold duration")
                        if params['event'] && params['event']['autoClear'] == true
                                event.worklogs.create(:user => user, :comment => "Clearing event by autoclear rule - #{params['event']['autoClearRuleName']} - #{params['event']['autoClearRuleID']} ")
                        end
                        event.worklogs.create(:user => user, :comment => "Event cleared")
                else
                        updated = event.update(:eventStatus => 'CLEARED', :clearedTime => Time.now.utc)
                        if params['event'] && params['event']['autoClear'] == true
                                event.worklogs.create(:user => user, :comment => "Clearing event by autoclear rule - #{params['event']['autoClearRuleName']} - #{params['event']['autoClearRuleID']} ")
                        end
                        event.worklogs.create(:user => user, :comment => "Event cleared")
                end

        logger.debug( "CLEAR : #{updated.to_json}")
        # find where all the eventID exists and delete them from events array
                insight_inc_ids = event.insightIncidentids
                if ! insight_inc_ids.nil?
                        begin
                                insight_inc_ids.each do |insight_inc_id|
                                        insight_inc = Incident.read(mode: :primary).find(insight_inc_id)
                                        if ! insight_inc.nil?
                                                logger.debug ( "Event present in insight_incident :ID: #{insight_inc_id}")
                                                insight_inc.with_lock do
                                                        insight_inc.pull(events: event[:id])
                                                        insight_inc.save!
                                                end
                                                logger.debug ( "Event removed from insight_incident :ID: #{insight_inc_id}")
                                                if insight_inc['events'].count == 0
                                                        logger.debug (" Deleting Incident ")
                                                        insight_inc.delete
                                                end
                                        end
                                end
                        rescue => error
                                logger.error("!!!!! Error handling Incident deletion processing !!!!! -- #{error.message}")
                        end
                end
                # find where all the eventID exists and delete them from events array. It is expected that warning events dont have incId
                if  ! event.incId.nil? # Individual alert
                        logger.debug("Clearing individual Alert")
                        begin
                                bpincident = Event.read(mode: :primary).find(event.incId )
                                if bpincident
                                        logger.debug( " #{bpincident['events']} :ID: #{event['id']}")
                                                bpincident.pull(groupevents: event[:id])
                                                bpincident.worklogs.create(:user => "AlertMan System" , :comment => "Removing event #{event.id} from group")
                                                # check if events array is empty. if yes, mark as inactive
                                                bpincident = Event.read(mode: :primary).find(event.incId )
                                if bpincident['groupevents'].empty?
                                                        logger.debug("Events empty in incident")
                                                        if ( bpincident['severity'] == 'CRITICAL' and  bpincident['isStage'] == true and bpincident['stageDuration'].to_i > Time.now.utc.to_i)
                                                                bpincident.update(:eventStatus => 'CLEARED', :clearedTime => Time.now.utc, :severity => 'WARNING')
                                                                bpincident.worklogs.create(:user => user, :comment => "Changing severity to WARNING as event cleared within hold duration")
                                                        else
                                                                bpincident.update(:eventStatus => "CLEARED" , :clearedTime => Time.now.utc)
                                                                bpincident.worklogs.create(:user => user, :comment => "Event cleared")
                                                        end
                                        else
                                        logger.debug("Events not empty in incident")
                                end
                                        logger.debug( "AFTER  #{bpincident['groupevents']}")
                                end
                        rescue => error
                                logger.error("!!!!! Error handling BPIncident deletion processing !!!!! -- #{error.message}")
                        end
                else # grouped alert. Need to clear all OPEN child alerts
                        # Find all child alerts
                        if ! event.groupevents.nil? && ! event.groupevents.empty?
                                logger.debug("Clearing group Alert")
                                event.groupevents.each do |indevent|
                                        logger.debug("Clearing individual Alert from group - #{indevent}")
                                        iEvent = Event.find(indevent)
                                        iEvent.update(:eventStatus => "CLEARED" , :clearedTime => Time.now.utc)
                                        iEvent.worklogs.create(:user => user, :comment => "Event cleared by Parent Event")
                                end
                        end
                end
        end

        # Use callbacks to share common setup or constraints between actions.
        def set_event
                @event = Event.read(mode: :secondary_preferred).find(params[:id])
        end

        # Never trust parameters from the scary internet, only allow the white list through.
        def event_params
                params.require(:event).permit( :entity, :ipAddress, :serviceName, :severity, :alertSummary, :alertNotes, :ticketStatus, :jsdticketNumber, :eventSource, :firstTime, :eventStatus, :eventID, :eAck, :impact, :rca, :eventGroups)
                end
                def event_params_manual
                        params.require(:event).permit( :entity, :serviceName, :severity, :alertSummary, :alertNotes, :jsdticketNumber, :eventSource, :firstTime)
        end

        def hnp_ticket_status
                params.require(:event).permit( :ticket, :status)
        end
end
