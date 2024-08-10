from datetime import datetime

field_mapping = {
        "Time" : 0,
        "SourceIP": 1,
        "DestinationIP": 2,
        "SourcePort": 3,
        "DestinationPort": 4,
        "Protocol": 5,
        "TrafficDestination": 6,
        "TrafficAction": 7,
        "Priority": 8,
        "BytesSent": 9,
        "BytesReceived": 10,
        "PacketsSent": 11,
        "PacketsReceived": 12,
    }
    
def processData(dataList,log_line_filter):
    parsed_lines = []
    log_size = 0
    metadata = {
        "SystemId": dataList["systemId"],
        "MacAddress": dataList["macAddress"],
        "ResourceCategory": dataList["category"],
        "ResourceId": dataList["resourceId"],
        "OperationName": dataList["operationName"],
        "Version": dataList["properties"]["Version"],
    }
    for rule in dataList["properties"]["flows"]:
        metadata["Rule"] = rule["rule"]
        for mac in rule["flows"]:
            metadata["MacAddress"] = mac["mac"]
            for flow_tuple in mac["flowTuples"]:
                data = flow_tuple.split(',')
                formatted_line = {field: data[index] for field, index in field_mapping.items()}
                datetime_obj = datetime.utcfromtimestamp(int(formatted_line['Time']))
                formatted_line['Time'] = datetime_obj.strftime('%Y-%m-%d %H:%M:%S')
                formatted_line["TrafficDestination"] = "Inbound" if formatted_line["TrafficDestination"] == "I" else "Outbound"
                formatted_line["Protocol"] = "TCP" if formatted_line["Protocol"] == "T" else "UDP"
                formatted_line["TrafficAction"] = "Accept" if formatted_line["TrafficAction"] == "A" else "Denied"
                formatted_line.update(metadata)
                parsed_line,_ = log_line_filter(formatted_line)
                parsed_lines.append(parsed_line)
                log_size+= _
    return parsed_lines,log_size