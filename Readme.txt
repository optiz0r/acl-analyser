= ACL Analyser =

== Usage Instructions ==

•	Extract the zip file and open the index.html file in a decent browser
	(chrome works, firefox probably will, IE probably wont).

•	Paste the output of “show access-list” from the context in question into the top box

•	Wait for the output to be generated
	(this may take couple minutes for a large context)

•	Copy/paste the output into the ACE tab of the excel spreadsheet

•	Refresh the pivot tables.
	(now, and any time the ACE tab is changed)

•	Look at the “unused rules” and “unused ports” tabs to see things which could be removed.

If you wish to send the resulting spreadsheet around, it may be useful to provide definitions for objects, object groups and service groups. The webpage will also parse the relevant show commands so that output can be pasted into the relevant tabs of the spreadsheet.