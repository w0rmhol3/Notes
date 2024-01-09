## API Testing
- Important due to vulnerabilities may lead to undermining website’s CIA.
- First can start by identifying API endpoints.
- eg: `GET /api/books HTTP/1.1`
  - The API endpoint of this example is within `/api/books`.
  - The web application interacts with the endpoint to retrieve its data.
- Next, determine how to interact with the endpoint.
- Can be done through constructing HTTP requests to test the API.

## Important Information to Find
- Input data that the API processes
- Types of data that the API accepts (HTTP methods, media format)
- Rate limit and Authentication mechanism

## API Documentation
- Human-Readable Form
- Machine-Readable Form (JSON, YAML)
- Mostly publicly available
- If not publicly available, can also be accessed through the API itself.
- Use burp scanner to crawl API.
- If endpoint is found, base path should also be investigated.

## Machine Readable Documentation
- Can use burp scanner to crawl and audit the JSON/YAML file.
- Can use specialized tool like Postman or SoapUI to test documentation endpoints.

## Best Practice
- Browse through sources to validate API, due to some API documentation are out of date.
- Use tools to locate and identify API endpoints.
- Burp scanner, JS Link Finder Bapp.
- Interact with API endpoints with burp repeater/intruder.
- Review error messages and responses.

## Supported HTTP Methods In API
- API endpoints may support different HTTP methods, so test on all endpoints
  - eg: Get – Retrieves data.
  - Patch – Applies partial changes to resource
  - Options – Retrieve information on the type of request headers supported.
- Changing the Content-Type header may lead to flaw bypass, information disclosure or processing logic flaw.

## Fuzzing Hidden Endpoint
- Fuzz hidden endpoint through identified endpoint.
- eg: use burp intruder and wordlists to fuzz the identified endpoint `PUT /api/user/update` by keeping position of the `/update` path with other functions such as delete or add.

## Mass Assignment/Auto-Binding Vulnerability
- Inadvertently creates hidden parameters.
- May cause supporting of unintended processed parameters.
- Eg: `PATCH /api/users/` request that allows the modification of the username and email, but the `GET /api/users/123` request will be able to retrieve id, name, email and isAdmin JSON data. This might indicate that the id and isAdmin JSON data is bound to the users object within the updated username and email parameter.
- To test it, add the isAdmin parameter into the `PATCH /api/users/` request along with invalid parameter value and observe the behavior.

## Preventing Vulnerabilities in API
- Secure documentation if API is not supposed to be publicly accessible.
- Keep documentation up to date for testers.
- Apply allowlist of HTTP methods.
- Validate Content-Type expected for each requests.
- Use generic error.
- Use protective measures on all version of API instead of only production ones.

## Server-Side Parameter Pollution
- Some system with internal API that are not accessible through the internet.
- Server-Side Parameter Pollution occurs when a website embeds user input within server side request to API without proper encoding.
- It allows attackers to override existing parameters, modify application behaviour, and access unauthorized data.
- Can be through query, form fields, headers, and url path parameters.
- Use special characters like `#, &, =` to test parameter pollution by observing application responses.
  - eg:  A application request GET /userSearch?name=peter&back=/home and retrieves data through GET /users/search?name=peter&publicProfile=true 
  - By adding # and url encode it and modify the request to `GET /userSearch?name=peter%23foo&back=/home` it will process `GET /users/search?name=peter#foo&publicProfile=true`
  - It will be able to remove the requirement of setting `publicProfile=true` and allow attacker to gain data of non-public profiles.
  - If found another parameter, test the API by adding it into the query strings:
  - `/users/search?name=peter&email=foo#foo&publicProfile=true`
- May also use Path Traversal method to exploit the parameter value.
  - eg: `GET /edit_profile.php?name=peter`
  - response: `GET /api/private/users/peter` 
  - modified value: `GET /edit_profile.php?name=peter%2f..%2fadmin`
  - response: `GET /api/private/users/peter/../admin`

## Overriding existing Parameter
- Add another the same parameter with different value
- eg: `GET /userSearch?name=peter&name=carlos&back=/home`
- Depending on how the parameter is processed, the output is different.
- PHP: only parse the last parameter.
- ASP.NET: combines both parameters.
- Node.js: only parse the first parameter.

## Server-side parameter pollution on Structured Data Format
- Attacker can exploit JSON or XML file by injecting unexpected structured data.
- Occurs when server-side JSON data is not properly sanitized.
- Eg: a application that edit profile with a POST request of “name” parameter with a value, without proper sanitization, the attacker can add another parameter such as “access_level” with value like “administrator”.

## Preventing Server-Side Parameter Pollution
- Use an allowlist to define characters that does not require encoding.
- Ensure all user input are encoded before included in server-side request.
- Ensure all inputs amend to the required format and structure.