import sys, os, re, gzip, json, urllib.parse, urllib.request, traceback, datetime, calendar, logging, hashlib, ast
import azure.functions as func
from base64 import b64decode

logtype_config = None
s247_datetime_format_string = None
log_size=0

def get_timestamp(datetime_string):
    try:
        datetime_data = datetime.datetime.strptime(datetime_string[:26], s247_datetime_format_string)
        timestamp = calendar.timegm(datetime_data.utctimetuple()) *1000 + int(datetime_data.microsecond/1000)
        return int(timestamp)
    except Exception as e:
        return 0

def is_filters_matched(formatted_line):
    if 'filterConfig' in logtype_config:
        for config in logtype_config['filterConfig']:
            if config in formatted_line:
                if re.findall(logtype_config['filterConfig'][config]['values'], formatted_line[config]):
                    val = True
                else:
                    val = False

                if (logtype_config['filterConfig'][config]['match'] ^ (val)):
                    return False
    return True

def log_line_filter(formatted_line):
    if masking_config:
        apply_masking(formatted_line)
    if hashing_config:
        apply_hashing(formatted_line)
    if derived_eval:
        derivedFields(formatted_line)

def get_json_value(obj, key, datatype=None):
    if key in obj or key.lower() in obj:
        if datatype and datatype == 'json-object':
            arr_json = []
            child_obj = obj[key]
            if type(child_obj) is str:
                try:
                    child_obj = json.loads(child_obj, strict=False)
                except Exception:
                    child_obj = json.loads(child_obj.replace('\\', '\\\\'), strict=False)

            for child_key in child_obj:
                arr_json.append({'key' : child_key, 'value': str(child_obj[child_key])})
            return arr_json
        else:
            return obj[key] if key in obj else obj[key.lower()]
    elif '.' in key:
        parent_key = key[:key.index('.')]
        child_key = key[key.index('.')+1:]
        child_obj = obj[parent_key if parent_key in obj else parent_key.capitalize()]
        if type(child_obj) is str:
            try:
                child_obj = json.loads(child_obj, strict=False)
            except Exception:
                child_obj = json.loads(child_obj.replace('\\','\\\\'), strict=False)
        return get_json_value(child_obj, child_key)

def json_log_parser(lines_read):
    global log_size
    log_size = 0
    parsed_lines = []
    for event_obj in lines_read:
        try:
            formatted_line = {}
            json_log_size = 0
            for path_obj in logtype_config['jsonPath']:
                value = get_json_value(event_obj, path_obj['key' if 'key' in path_obj else 'name'], path_obj['type'] if 'type' in path_obj else None)
                if value:
                    formatted_line[path_obj['name']] = value
                    json_log_size+= len(str(value))
            if not is_filters_matched(formatted_line):
                continue
            log_size += json_log_size
            formatted_line['_zl_timestamp'] = get_timestamp(event_obj[logtype_config['dateField']])
            if 'resourceId' in event_obj:
                formatted_line['s247agentuid'] = event_obj['resourceId'].split('/')[4]
                event_obj['resourceId'] = event_obj['resourceId'].lower()
            log_line_filter(formatted_line)
            parsed_lines.append(formatted_line)
        except Exception as e:
            print('unable to parse event message : ',event_obj)
            traceback.print_exc()
            pass
    return parsed_lines, log_size

def send_logs_to_s247(gzipped_parsed_lines, log_size):
    header_obj = {'X-DeviceKey': logtype_config['apiKey'], 'X-LogType': logtype_config['logType'],
                  'X-StreamMode' :1, 'Log-Size': log_size, 'Content-Type' : 'application/json', 'Content-Encoding' : 'gzip', 'User-Agent' : 'AZURE-Function'
    }
    upload_url = 'https://'+logtype_config['uploadDomain']+'/upload'
    request = urllib.request.Request(upload_url, headers=header_obj)
    s247_response = urllib.request.urlopen(request, data=gzipped_parsed_lines)
    dict_responseHeaders = dict(s247_response.getheaders())
    if s247_response and s247_response.status == 200:
        logging.info('%s :All logs are uploaded to site24x7', dict_responseHeaders['x-uploadid'])
    else:
        logging.info('%s :Problem in uploading to site24x7 status %s, Reason : %s', dict_responseHeaders['x-uploadid'], s247_response.status, s247_response.read())

def apply_masking(formatted_line):
    global log_size
    try:
        for config in masking_config:
            adjust_length = 0
            mask_regex = masking_config[config]['regex']
            if config in formatted_line:
                field_value = str(formatted_line[config])
                for matcher in re.finditer(mask_regex, field_value):
                    if matcher:
                        for i in range(mask_regex.groups):
                            matched_value = matcher.group(i + 1)
                            if matched_value:
                                start = matcher.start(i + 1)
                                end = matcher.end(i + 1)
                                if start >= 0 and end > 0:
                                    start = start - adjust_length
                                    end = end - adjust_length
                                    adjust_length += (end - start) - len(masking_config[config]['string'])
                                    field_value = field_value[:start] + masking_config[config]['string'] + field_value[end:]
                formatted_line[config] = field_value
                log_size -= adjust_length
    except Exception as e:
        traceback.print_exc()


def apply_hashing(formatted_line):
    global log_size
    try:
        for config in hashing_config:
            adjust_length = 0
            mask_regex = hashing_config[config]['regex']
            field_value = str(formatted_line[config])
            if config in formatted_line:
                for matcher in re.finditer(mask_regex, field_value):
                    if matcher:
                        for i in range(mask_regex.groups):
                            matched_value = matcher.group(i + 1)
                            if matched_value:
                                start = matcher.start(i + 1)
                                end = matcher.end(i + 1)
                                if start >= 0 and end > 0:
                                    start = start - adjust_length
                                    end = end - adjust_length
                                    hash_string = hashlib.sha256(matched_value.encode('utf-8')).hexdigest()
                                    adjust_length += (end - start) - len(hash_string)
                                    field_value = field_value[:start] + hash_string + field_value[end:]
                formatted_line[config] = field_value
                log_size -= adjust_length
    except Exception as e:
        traceback.print_exc()


def derivedFields(formatted_line):
    global log_size
    try:
        for items in derived_fields:
            for each in derived_fields[items]:
                if items in formatted_line:
                    match_derived = each.search(formatted_line[items])
                    if match_derived:
                        match_derived_field = match_derived.groupdict(default='-')
                        formatted_line.update(match_derived_field)
                        for field_name in match_derived_field:
                            log_size += len(formatted_line[field_name])
                        break
    except Exception as e:
        traceback.print_exc()


def main(eventMessages: func.EventHubEvent):
    try:
        global logtype_config, s247_datetime_format_string,masking_config, hashing_config, derived_eval, derived_fields, log_size
        cardinality = 'many'
        if type(eventMessages) != list:
            eventMessages = [eventMessages]
            cardinality = 'one'
        for eventMessage in eventMessages:
            payload = json.loads(eventMessage.get_body().decode('utf-8'))
            log_events = payload['records'] if cardinality == 'many' else payload[0]['records']
            try:
                print("Type :" + str(type(os.environ['debugMode'])))
                if ast.literal_eval(os.environ['debugMode']):
                    print("Debug event : " + str(log_events[0]))
            except Exception as e:
                print("Exception in debug " + str(e))
                pass
            log_category = ''
            if 'category' in log_events[0] or 'Category' in log_events[0]:
                log_category = (log_events[0]['category' if 'category' in log_events[0] else 'Category']).replace('-', '_')
                print("log_category" + " : "+ log_category)
                log_category = 'S247_'+log_category

            elif 'Identifier' in os.environ:
                for each in os.environ['Identifier'].split(","):
                    if each in log_events[0]:
                        log_category = 'S247_'+log_events[0][each]
                        break
                      
            if log_category in os.environ:
                print("log_category found in input arguments")
                logtype_config = json.loads(b64decode(os.environ[log_category]).decode('utf-8'))
                s247_datetime_format_string = logtype_config['dateFormat']
            elif 'logTypeConfig' in os.environ:
                logtype_config = json.loads(b64decode(os.environ['logTypeConfig']).decode('utf-8'))
                s247_datetime_format_string = logtype_config['dateFormat']
            else:
                return
            masking_config = logtype_config['maskingConfig'] if 'maskingConfig' in logtype_config else None
            hashing_config = logtype_config['hashingConfig'] if 'hashingConfig' in logtype_config else None
            derived_eval = logtype_config['derivedConfig'] if 'derivedConfig' in logtype_config else None

            if derived_eval:
                try:
                    derived_fields = {}
                    for key in derived_eval:
                        derived_fields[key] = []
                        for values in derived_eval[key]:
                            derived_fields[key].append(re.compile(values.replace('\\\\', '\\').replace('?<', '?P<')))
                except Exception as e:
                    print("Error in dfields")
            if masking_config:
                for key in masking_config:
                    masking_config[key]["regex"] = re.compile(masking_config[key]["regex"])

            if hashing_config:
                for key in hashing_config:
                    hashing_config[key]["regex"] = re.compile(hashing_config[key]["regex"])
            
            if "filterConfig" in logtype_config:
                for field in logtype_config['filterConfig']:
                    temp = []
                    for value in logtype_config['filterConfig'][field]['values']:
                        temp.append(re.compile(value))
                    logtype_config['filterConfig'][field]['values'] = '|'.join(x.pattern for x in temp)
                    
            if 'jsonPath' in logtype_config:
                parsed_lines, log_size = json_log_parser(log_events)

            if parsed_lines:
                gzipped_parsed_lines = gzip.compress(json.dumps(parsed_lines).encode())
                send_logs_to_s247(gzipped_parsed_lines, log_size)
    except Exception as e:
        traceback.print_exc()
        raise e
