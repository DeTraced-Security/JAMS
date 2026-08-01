How to contribute

I'm really glad you're reading this, because we need volunteer developers to help this project come to fruition.

A list of resources will be published shortly for how to contribute to the project.

Testing

This section will be written shortly! For now, manual testing of the API is needed.

Submitting changes

Please send a GitHub Pull Request to opengovernment with a clear list of what you've done (read more about pull requests). Please follow our coding conventions (below) and make sure all of your commits are atomic (one feature per commit).

Always write a clear log message for your commits. One-line messages are fine for small changes, but bigger changes should look like this:

$ git commit -S -m "A brief summary of the commit
>
> A paragraph describing what changed and its impact."

Coding conventions

Start reading our code and you'll get the hang of it. We optimize for readability and secuity:

• We indent using four spaces (hard or soft tabs)
• All commits must be signed, either over web, SSH, or GPG. Any commits as of 2025-04-23T03:38:09Z that are not signed will not be accepted*. Pull Requests, included.
• We avoid logic in views, putting HTML generators into helpers
• Use correct commenting styles, multi-line should use /** */ and should concisely describe why it works, avoid explaining the what it does unless the method may appear obscure.
• We ALWAYS put spaces after list items and method parameters ([1, 2, 3], not [1,2,3]), around operators (x += 1, not x+=1), and around hash arrows.
• This is open source software. Consider the people who will read your code, and make it look nice for them. It's sort of like driving a car: Perhaps you love doing donuts when you're alone, but with passengers the goal is to make the ride as smooth as possible.
• When writing API responses, a DTO for it's correlating format can be found in the Utility folder.
• We use strong typing, so ensure that all variables, functions, etc. are using the correct explicit type (const example: string = "asdf";, ... async (req: Request, res: Response) ...).

* Setting up commit signing can be found can be under GitHub's Signing Commits documentation.

Practising Secure Coding:

While we acknowledge readability, there are cases where we apply security standards that may lead to obscure code.
In such cases, the standards applied are as followed and may reference OWASP ASVS:

Threat Matrix
Our current working threat matrix is defined as below, and may be subject to change


Threat
Risk Description
Mitigation/Control
ASVS Reference

1. Obscured Readability Due to Security Practices
Security measures may lead to code that is harder to read or understand, which can increase the chances of security flaws.
- Maintain balance between readability and security standards.
- OWASP ASVS: General Practice

2. Unnecessary Supply Chain Dependencies
Overuse of libraries for simple methods increases the attack surface due to more dependencies and potential vulnerabilities.
- Avoid installing external libraries for simple tasks.
- OWASP ASVS: General Practice

3. Insufficient Input and Output Handling
Failure to clearly define how to handle data input and output may lead to unexpected behaviors or vulnerabilities.
- Ensure input/output handling is defined by type, content, and relevant laws/policies.
- ASVS 4.0.3, 1.5.1

4. Deserialization Vulnerabilities
Using serialization with untrusted clients can open the application to attacks like object injection and deserialization flaws.
- Avoid serialization with untrusted clients. - Implement integrity controls, encryption, and proper validation when serialization is necessary.
- ASVS 4.0.3, 1.5.2

5. Lack of Input Validation on Trusted Service Layer
Failing to enforce input validation at the service layer may result in improper data processing, leading to injection attacks.
- Enforce robust input validation on trusted service layers.
- ASVS 4.0.3, 1.5.3

6. Inconsistent or Poor Logging Practices
Improper or inconsistent logging may obscure security incidents or make them harder to detect.
- Implement a standardized logging format and consistent approach across the system.
- ASVS 4.0.3, 1.7.1

7. Outdated/Insecure Components in Build Pipeline
The presence of outdated, insecure, or vulnerable components can introduce new risks to the application.
- Set up warnings in the build pipeline for out-of-date or insecure components and take immediate corrective action.
- ASVS 4.0.3, 1.14.3

8. Use of Unsupported or Insecure Client-Side Technologies
Use of deprecated or insecure client-side technologies can introduce vulnerabilities or make the system incompatible.
- Ensure that the application does not use unsupported, insecure, or deprecated client-side technologies (e.g., Flash, ActiveX, Java applets).
- ASVS 4.0.3, 1.14.6



───

Key Notes for Secure Coding:
• Input Validation: Always validate input on the trusted service layer to prevent attacks like SQL injection, XSS, etc. Input validation must consider the type, content, and specific laws/regulations that apply.
• Serialization Integrity: Avoid using serialization for communication with untrusted clients. If unavoidable, ensure the integrity and confidentiality of serialized data.
• Library Dependency: Use libraries only when necessary, and avoid bloating the application with unnecessary dependencies to minimize the risk of introducing vulnerabilities.
• Logging and Monitoring: Use consistent and structured logging to monitor activities and catch security incidents early.
• Build Pipeline Security: Ensure the build pipeline detects and flags outdated or insecure components before they are deployed into production.
• Client-Side Technologies: Regularly audit client-side technologies to ensure they are up-to-date and secure, and avoid deprecated or insecure components.

Thanks,
DeTraced Staff
