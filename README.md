Welcome to the MicrosoftInternshipProject_Indu wiki!

Synopsis: Motive of this project is to analyse and mitigate or respond to the cyber threats which we see in wide variety of organizations. Using Microsoft services like - Microsoft Sentinel, Power BI and Azure Active Directory

This project allows a security team to monitor and investigate suspicious terminated user sign - in and azure activities using Azure Sentinel and also allows to automate response action using playbooks/logic apps and finally export the data as reports and visualize them in Power BI service.

Summary:

The idea of this project is to investigate and automate the security response actions to suspicious azure user activities and user sign-ins using Azure Services like Azure Sentinel, Azure Logic APPS and Power BI.

I have used Azure Sentinel Service to monitor and Investigate suspicious terminated user sign-ins and activities. I made use of a feature called "Watchlist" in Azure Sentinel wherein I have created a watchlist which contains a csv file with list of all the terminated users of an organization. This watchlist will be used as a lookup data in the below Analytical rules to generate incidents in Azure Sentinel.

I have created two use cases or Analytical rules to find sign-ins and azure activity done by the terminated users after leaving an organization.

Use Case 1 : MonitorTerminatedUserLogin and azure activity

The Analytical rule "MonitorTerminatedUserLogin and azure activity" shows all the azure activities done by the terminated user and triggers an incident in azure sentinel for investigation by the security team

Description: This analytical rule monitors users from terminated users watchlist and triggers an alert and incident when there is a successful login followed by azure activity for the terminated users from the watchlist.

Tactics: Credential Access

KQL Query

let TerminatedUser =_GetWatchlist('MonitorTerminatedUsersList'); AzureActivity | where OperationName !='' and ActivityStatus in ("Succeeded","Failed","Started") | where Caller != '' | extend Account_Entity = Caller | extend IP_Entity = CallerIpAddress | join kind = inner TerminatedUser on $left.Caller ==$right.Caller | where Caller == "CompromisedUser@indusuresh50gmail.onmicrosoft.com" | summarize count() by TimeGenerated,OperationId,OperationName,Caller,IP_Entity | extend Account_Entity = Caller | extend CallerIpAddress = IP_Entity

Use Case 2: MonitorTerminatedUser Sign in activity

The Analytical rule "MonitorTerminatedUser Sign in activity" monitors the terminated user sign-in logs and triggers an incident when there is a sign-in by the terminated user from the watchlist.

Description: This analytical rule monitors users from terminated users watchlist and triggers an alert and incident when there is a successful login for the terminated users from the watchlist.

Tactics: Credential Access

KQL Query

let TerminatedUser =_GetWatchlist('MonitorTerminatedUsersList'); SigninLogs | where ResultType ==0 | project ResultType,Identity,AlternateSignInName,TimeGenerated,ResultDescription | join kind=inner TerminatedUser on ($left.AlternateSignInName ==$right.Caller) | where AlternateSignInName == "CompromisedUser@indusuresh50gmail.onmicrosoft.com" | extend AlternateSignInName = Caller

The motive of the above use cases is to get lookup data from the watchlist for all the terminated users of the organization and monitor if there are sign-in activity followed by azure activity for the users. If the scenario matches it triggers Incidents and having the automation rule in place to change the status of incident from new to active and assign the owner to that incident followed by changing the severity of the incident to high so that the analyst will be able to work on it with high priority.

Once the Security team investigates the incident and concludes the user activity and sign-in is suspicious then they can run a playbook/logic app to disable the terminated user account which is still active in the Azure Active Directory.
As a response action I have created a playbook called "Disable_CompromisedTerminatedUsers", which will immediately take action and disable the terminated/compromised user account in Azure Active Directory.

Finally, I have used Power BI service to export the terminated user sign-ins and azure activity as reports and generate visualizations for clear understanding and audit purpose using M query in Azure Sentinel, which allows security team to maintain end to end sign-in and azure activity log reports of the terminated users.
