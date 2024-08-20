from azure.data.tables import TableClient,UpdateMode
from azure.core.exceptions import ResourceExistsError,HttpResponseError
import logging


class check_point:
    def __init__(self,connection_string):
        self.connection_string = connection_string
        self.table_name = "check_points"

    def entityMethod(self,partitionKey,rowKey,index):
        return {
            "PartitionKey" : partitionKey,
            "RowKey" : rowKey,
            "check_pointIndex" : index
        }


    def put_check_point(self,entityObj):
        with TableClient.from_connection_string(self.connection_string,self.table_name) as table_client:
            try:
                table_client.create_entity(entity=entityObj)
            except ResourceExistsError:
                table_client.update_entity(mode=UpdateMode.REPLACE,entity=entityObj)

    def get_check_point(self,blob_details):
        with TableClient.from_connection_string(self.connection_string,self.table_name) as table_client:        
            try:
                result = table_client.get_entity(blob_details.get_partition_key(), blob_details.get_row_key())
                check_point = self.entityMethod(result['PartitionKey'],result['RowKey'],result['check_pointIndex'])
            except:
                check_point = self.entityMethod(blob_details.get_partition_key(),blob_details.get_row_key(),1)

            if check_point['check_pointIndex'] == 0:
                check_point['check_pointIndex'] = 1

            return check_point


