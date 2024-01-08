
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
- Exploiting the Cookie TrackingID header in applications.
- Example of a Blind SQLI exploit: `xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`.
- Attack strategies include using Boolean conditions to determine the true/false status of criteria, then brute-forcing based on responses.

## Error-Based SQLI
- Involves using error messages to extract or infer sensitive data.
- Boolean conditions may or may not be effective.

## OAST SQLI (Out-of-band Application Security Testing)
- A variant of Blind SQLI.
- Causes the server to interact with an external system under the attacker's control via another protocol.
- Often uses tools like Burp Collaborator.

## Checking Database Version
- MySQL: `SELECT @@version`
- Oracle: `SELECT * FROM v$version`
- PostgreSQL: `SELECT version()`

## Database Schema Queries
- `SELECT * FROM information_schema.tables`
- `SELECT * FROM information_schema.columns WHERE table_name = 'Users'`
