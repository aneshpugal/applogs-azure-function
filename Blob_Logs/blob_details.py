import re

class BlobDetails:
    def __init__(self, blob_path,container_name):
        if blob_path:
            pattern = re.compile(r".*SUBSCRIPTIONS/(?P<subId>[^/]+)/RESOURCEGROUPS/(?P<resourceGroup>[^/]+)/PROVIDERS/(?P<resourceNamespace>[^/]+)/(?P<serviceGroup>[^/]+)/(?P<serviceName>[^/]+)/y=(?P<blobYear>[^/]+)/m=(?P<blobMonth>[^/]+)/d=(?P<blobDay>[^/]+)/h=(?P<blobHour>[^/]+)/m=(?P<blobMinute>[^/]+)(?:/macAddress=(?P<mac>[^/]+))?.*")
            match = pattern.match(blob_path)
            if match:
                self.subscription_id = match.group("subId")
                self.resource_group = match.group("resourceGroup")
                self.resource_namespace = match.group("resourceNamespace")
                self.service_group = match.group("serviceGroup")
                self.service_name = match.group("serviceName")
                self.year = match.group("blobYear")
                self.month = match.group("blobMonth")
                self.day = match.group("blobDay")
                self.hour = match.group("blobHour")
                self.minute = match.group("blobMinute")
                if match.group("mac") != None:
                    self.mac = match.group("mac")
            self.container_name = container_name

    def get_partition_key(self):
        if hasattr(self,"mac"):
            return f"{self.subscription_id.replace('-', '_')}_{self.resource_group}_{self.service_name}_{self.mac}"
        else:
            return f"{self.subscription_id.replace('-', '_')}_{self.resource_group}_{self.container_name}"
    def get_row_key(self):
        return f"{self.year}_{self.month}_{self.day}_{self.hour}_{self.minute}"

    def __str__(self):
        return f"{self.resource_group}_{self.service_name}_{self.day}_{self.hour}"
