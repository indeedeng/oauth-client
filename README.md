Authorization Client
=============================
This is for developers that are building applications and want to leverage Indeed OAuth in their process.

The code are based on the Indeed authorization documentations (linked below):
https://developer.indeed.com/docs/authorization/3-legged-oauth  
https://developer.indeed.com/docs/authorization/2-legged-oauth


How to use
=============================
## Gradle
normal users: ``implementation 'com.indeed:oauth-client'``  

## Configuration
**NOTE 1:** Make sure you followed the Indeed [Authorization documentation](https://developer.indeed.com/docs/authorization/3-legged-oauth#get-a-client-id-and-secret) to get your application client id
```java
@Configuration
public class ApplicationConfig {
    public static final String INDEED_SECURE_HOST_NAME = "https://secure.indeed.com";
    @Bean
    TwoLeggedOAuthClient twoLeggedOAuthClient() throws IOException, GeneralException {
        return create2LeggedOAuth2Client(
                clientId,
                clientSecret,
                INDEED_SECURE_HOST_NAME);
    }
    
    @Bean
    ThreeLeggedOAuthClient threeLeggedOAuthClient() throws IOException, GeneralException {
        return create3LeggedOAuth2Client(
                clientId,
                clientSecret,
                INDEED_SECURE_HOST_NAME);
    }
}
```

## Examples

### Get *Request an Authorization Code Link*

```java
public class Example {
    @Autowired
    ThreeLeggedOAuthClient threeLeggedOAuthClient;

    URI get3LeggedOAuthCodeUrl(final String state) throws URISyntaxException {
        return new ResponseEntity<>(
                threeLeggedOAuthClient.getAuthorizeUrl(
                        state,
                        new String[]{EMAIL, OFFLINE_ACCESS, EMPLOYER_ACCESS},
                        null,
                        clientRedirectUrl),
                HttpStatus.OK);
    }
}
```

### Request Access Token
```java
public class Example {
    @Autowired
    ThreeLeggedOAuthClient threeLeggedOAuthClient;
    @Autowired
    TwoLeggedOAuthClient twoLeggedOAuthClient;

    OIDCTokens get3LeggedAccessToken(final String code) throws IOException, URISyntaxException, ParseException {
        return threeLeggedOAuthClient.getUserOAuthCredentials(code, clientRedirectUrl);
    }

    OIDCTokens get2LeggedAccessToken() throws IOException, ParseException {
        return twoLeggedOAuthClient.getAppOAuthCredentials(new String[] {EMPLOYER_ACCESS});
    }
}
```

### Represent Employer (Get Employer Access Token)
```java
public class Example {
    @Autowired
    ThreeLeggedOAuthClient threeLeggedOAuthClient;
    @Autowired
    TwoLeggedOAuthClient twoLeggedOAuthClient;

    OIDCTokens get3LeggedEmployerToken(final String code, final String employerId) throws URISyntaxException, IOException, ParseException {
        return threeLeggedOAuthClient.getEmployerOAuthCredentials(code, clientRedirectUrl, employerId);
    }

    OIDCTokens get2LeggedEmployerToken(final String employerId) throws IOException, ParseException {
        return twoLeggedOAuthClient.getEmployerOAuthCredentials(employerId, new String[] {EMPLOYER_ACCESS});
    }
}
```

### Refresh Access Token
```java
public class Example {
    @Autowired
    ThreeLeggedOAuthClient threeLeggedOAuthClient;

    OIDCTokens refresh3LAccessToken(final String refreshToken) throws IOException, ParseException {
        return threeLeggedOAuthClient.refreshOAuthCredentials(refreshToken);
    }
}
```

When to use
=============================
[Authorization Documentation](https://developer.indeed.com/docs/authorization/)

## Authorization Code Flow (3-legged OAuth)
> Use this OAuth flow in applications that act on behalf of another user. Indeed displays an OAuth consent screen for users to login and give applications specific permissions.

## Client Credentials Flow (2-legged OAuth)
> Use this OAuth flow in applications that act on behalf of the Indeed user that registered the app and the employer accounts associated with that Indeed user.

Getting Help
=============================
If an issue doesn’t already exist that describes the change you want to make, we recommend creating one and project maintainers will get back to you as soon as we can.

Contributing
=============================
Read the Code of Conduct and Contact the Maintainers before making any changes or a PR. If an issue doesn’t already exist that describes the change you want to make, we recommend creating one. If an issue does exist, please comment on it saying that you are starting to work on it, to avoid duplicating effort.

Project Maintainers
=============================
[ahuangjm](https://github.com/ahuangJM)

Code of Conduct
=============================
This project is governed by the [Contributor Covenant v 1.4.1](https://www.contributor-covenant.org/)
Any questions can be directed to [opensource@indeed.com]()


License
=============================
Authorization Client is licensed under the [Apache 2 license](./LICENSE).

