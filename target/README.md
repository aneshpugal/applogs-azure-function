# Forwards Azure NSG logs from Azure Storage Account

Configure network security group (NSG) flow logs to be sent to [AppLogs](https://www.site24x7.com/help/log-management/) to monitor, analyze, and visualize network traffic in your Azure environment.

You can configure an automated deployment by following the steps mentioned in this [document](https://www.site24x7.com/help/log-management/azure-nsg-flow-logs.html).

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsite24x7%2Fapplogs-azure-function%2Fmaster%2Fdeployment%2Fsite24x7-azure-nsgflow-logs-deployment.json)

| Function | Description |
|---|---|
| Subscription | Choose your subscription mode. |
| Resource group | Create a new resource group with a name similar to Site24x7-Azure-Logs. | 
| Region | Choose a location. |
| Name | The function name will be prefilled. You don’t need to change it. |
| Blob connection string | Retrieve the connection string for the storage account where the NSG Flow logs are stored by following the steps mentioned in this [document](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal#view-account-access-keys). |
| Log Type Config | Navigate to the Site24x7 web client, select **Admin > Applogs > Log Profile**, then select the created log profile, and copy the code that appears on the screen as the input for the variable logtypeConfig. |
| Log Collection Start Time | Give collection time in Unix format (e.g., 1705989855). This setting determines when to collect logs. If no time is specified, it defaults to processing events created from the configuration time onward. |