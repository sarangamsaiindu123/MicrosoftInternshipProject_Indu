Welcome to the MicrosoftInternshipProject_Indu wiki!

Motive of this project is to analyse and mitigate or respond to the cyber threats which we see in wide variety of organizations. Using Microsoft services like - Microsoft Sentinel, Power BI and Azure Active Directory

I have created two use cases as detailed below with the purpose:

Use Case 1 : MonitorTerminatedUserLogin and azure activity

Description: This analytical rule monitors users from terminated users watchlist and triggers an alert and incident when there is a successful login followed by azure activity for the terminated users from the watchlist.

Tactics: Credential Access

KQL Query

let TerminatedUser =_GetWatchlist('MonitorTerminatedUsersList'); AzureActivity | where OperationName !='' and ActivityStatus in ("Succeeded","Failed","Started") | where Caller != '' | extend Account_Entity = Caller | extend IP_Entity = CallerIpAddress | join kind = inner TerminatedUser on $left.Caller ==$right.Caller | where Caller == "CompromisedUser@indusuresh50gmail.onmicrosoft.com" | summarize count() by TimeGenerated,OperationId,OperationName,Caller,IP_Entity | extend Account_Entity = Caller | extend CallerIpAddress = IP_Entity

Use Case 2: MonitorTerminatedUser Sign in activity

Description: This analytical rule monitors users from terminated users watchlist and triggers an alert and incident when there is a successful login for the terminated users from the watchlist.

Tactics: Credential Access

KQL Query

let TerminatedUser =_GetWatchlist('MonitorTerminatedUsersList'); SigninLogs | where ResultType ==0 | project ResultType,Identity,AlternateSignInName,TimeGenerated,ResultDescription | join kind=inner TerminatedUser on ($left.AlternateSignInName ==$right.Caller) | where AlternateSignInName == "CompromisedUser@indusuresh50gmail.onmicrosoft.com" | extend AlternateSignInName = Caller

The motive of the above use cases is to create a watchlist for all the terminated users of the organization and monitor if there are sign-in activity followed by azure activity for the users in the watchlist. If the scenario matches it triggers Incidents and having the automation rule in place to change the status of incident from new to active and assign the owner to that incident followed by changing the severity of the incident to high so that the analyst will be able to work on it with high priority.

As a response action I have created a playbook called "Disable_CompromisedTerminatedUsers", which will immediately take action and disable the terminated/compromised user account in Azure Active Directory.

I have also tried to use Power BI service to generate reports of the user sign-ins and the azure activity.

The entire use case scenario is implemented,executed and recorded as a video. The video file "MicrosoftInternshipProject_Indu.mp4" has also been uploaded in the git repository linked to this project.
