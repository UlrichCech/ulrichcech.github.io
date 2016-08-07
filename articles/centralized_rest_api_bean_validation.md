# Centralized REST-API exception handling with BeanValidation
by Ulrich Cech

## Initiation
In a REST API, the exception handling is very important. On the one hand we do not want to show the API-user meaningless
stack traces or the default error page from the Application Server. Besides, it is also a security risk to give a stack
trace outwards, as this publishes numerous internal implementation details, which makes an attack significantly easier.
Secondly, the REST API is also used by other programming languages beside Java, and the respective developers
can't/don't want to have to interpret any Java stack trace.

For this we want to provide meaningful and even evaluable errors, which simplify the use of the REST API and thus also
lead to a higher acceptance and usability of the individual REST API. This means that we want to provide correct and
appropriate HTTP status codes as well as a uniform error data structure. This structure can also be processed by
machines, e.g. with automatic status queries.

In this article, I want to introduce a solution, how to build a centralized exception handling for a REST API, which is
coupled with BeanValidation. I use exclusively the JavaEE7 standard (JAX-RS, JAXB for serialization in XML or JSON,
etc.), so no additional libraries are required.


## Centralized Exception Handling
First of all, we have to investigate where an exception can occur in our code. Potentially, this can happen anywhere,
because we have to take into account the CheckedExceptions and additionally any RuntimeExceptions, which can also be
thrown in Third Party libraries and which penetrate our code. We are aware of the CheckedExceptions by the compiler; but
we could find out the RuntimeExceptions only by analysis of each method, even by Third Libraries. Of course we don't want
to put "try / catch blocks" all around or at least in any REST API endpoint method. This leads to boilerplate code, thus
reducing the readability and maintainability. The following example shows this very clearly:

```java
@RequestScoped
@Path("users")
public class UsersResource {
 
    @Inject
    UserRepository userRepository;
 
    @POST
    public Response registerUser(User userRequest) {
        // try {
            User managedUser = userRepository.register(userRequest);
            URI uri = super.info.getAbsolutePathBuilder()
                    .path("/" + managedUser.getEmail()).build();
            return Response.created(uri).entity(managedUser).build();
        // } catch (Exception ex) {
        //     if (ex instanceof ExceptionA) {
        //         return <X>;
        //     }
        //     if (ex instanceof ExceptionB) {
        //         return <Y>;
        //     }
        //     usw.
        // }
    }
}
```

We would need to implement the deactivated code in each method, whereby we would also violate the DRY principle (Do not
Repeat Yourself), what we have to avoid as good developers.

Even if there is only one catch-block or one error situation to handle, the code which deals with the exception handling
is much more than the functional code, which is only 3 lines.

Fortunately at this point, JavaEE has already suitable mechanisms to treat the exception handling at a central location:

* Interceptors
* ExceptionMapper

A central, but minimalistic ExceptionInterceptor for HTTP-error code 500 (Internal server error), which returns the
textual error message of this error, could have the following structure:

```java
public class APIExceptionInterceptor {
 
    @AroundInvoke
    public Object handleException(InvocationContext context) {
        Object proceedResponse;
        try {
            proceedResponse = context.proceed();
        } catch (Exception ex) {
            return Response.serverError().entity(ex.getMessage()).build();
        }
        return proceedResponse;
    }
}
```

The Interceptor in all the REST resource classes is enabled through the `@Interceptor` annotation at class level . When
calling a REST method, the handleException()-method is called first, which then launches the code of the REST-method via
the line `proceedResponse = context.proceed();`. If now an exception is thrown during execution, it will be processed by
the "catch" block of the handleException()-method:

```java
@RequestScoped
@Path("users")
@Interceptor(APIExceptionInterceptor.class)  // <--- added interceptor annotation
public class UsersResource {
   // ...
}
```

**Note:** If we need more than one interceptor, they could be defined via the
annotation`@Interceptors({APIExceptionInterceptor.class, B.class, C.class})`, which takes a list of interceptor classes.
In addition, interceptors can be provided not only on class-level, but also on method-level. This is useful, if we need
some fine-grained control of the execution of interceptors.  
But, we want to handle exceptions on every method, so we need the class-level-annotation. And more important, our
ExceptionInterceptor whould be mentioned first in the list if interceptors in the `@Interceptors`annotation, because
then we can handle exceptions, which can occur in other interceptors, as well.  

Finally, we can define interceptors a little bit more elegant via Name-Binding/Interceptor-Binding, which is described
in detail in the following links:

* http://docs.oracle.com/javaee/7/api/javax/ws/rs/NameBinding.html
* http://docs.oracle.com/javaee/7/api/javax/interceptor/InterceptorBinding.html

This minimalistic approach now ???liefert?? gets us a response with HTTP-errorcode 500 ("Internal Server error") with
the textual error message of the exception. But this information helps us only ???bedingt???, but we ???immerhin??? have
a centralized solution with the stacktrace.
 
**Note:** The stacktrace is important for debugging. So, of course, we can log the exception to an error-log in the catch
clause.
 
On the server-side, we need to deal with exceptions, which cannot be handled by our ExceptionInterceptor. These could be
exceptions, which are thrown by the JAX-RS-framework before the HTTP-request reaches our Resource-class. In more detail,
this could be some of the following exceptions:

* `javax.ws.rs.NotFoundException` 
* `javax.ws.rs.NotAcceptableException`
* `javax.ws.rs.NotSupportedException`
* ...

In the package `javax.ws.rs`, there are some more exceptions, which should be handled accordingly, but we let them out
for clarity.

Ok, now we want to handle these exceptions and process them the same way as our `APIExceptionInterceptor`, so that we
can return a status-code and the error-message of the exception as well. For this, we use the
`javax.ws.rs.ext.ExceptionMapper`-interface. This generic interface could be implemented the following way:

```java
import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
 
@Provider
public class JAXRSNotFoundMapper implements ExceptionMapper<NotFoundException> {
 
    @Override
    public Response toResponse(NotFoundException ex) {
        return Response.status(Response.Status.NOT_FOUND)
                .entity(ex.getMessage()).build();
    }
}
```

```java
import javax.ws.rs.NotAcceptableException;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper; 
import javax.ws.rs.ext.Provider;
 
@Provider
public class JAXRSNotAcceptableMapper implements ExceptionMapper<NotAcceptableException> {
 
    @Override
    public Response toResponse(NotAcceptableException ex) {
        return Response.status(Response.Status.NOT_ACCEPTABLE)
                .entity(ex.getMessage()).build();
    }
}
```

All the other exceptions (e.g. `javax.ws.rs.NotSupportedException`) could be handled by an ExceptionMapper like the one
before.

With the annotation `@Provider` these mappers are registered automatically at server startup. So you need not to
register them in some XML-configuration file (like web.xml) anymore.

The ExceptionMappers do not work globally in the WebApplication. They only catch exceptions for URIs, which are below the
Base-URI of the JAX-RS-Application. This URI is configured here:

```java
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
 
@ApplicationPath("/api")
public class JAXRSConfiguration extends Application {
}
```

Now, this means, that the ExceptionMapper work for all URIs below `/api/`. In our example, we have currently only one
UsersResource with the following path:  
http://<server>:<port>/<context>/api/users

For example, if we would request the resource `http://<server>:<port>/<context>/api/accounts`, which currently does not
exists, then the server would produce a `NotFoundException`, which in turn would be caught and processed by our
ExceptionMapper... exactly, want we want the application to behave.


### Milestone 1
We are now in the position to catch and handle all kinds of exceptions, which are thrown elsewhere in our application.
For this, we use the ExceptionInterceptors, and the ExceptionMappers for the exceptions, which the JAX-RS-framework
throws. The interceptors and mappers generate a uniformly result (HTTP-statuscode and error-text of the exception).




## Converting the exceptions in a uniform response structure
In the last section, we took care about catching potentially all thrown exceptions. Next, we need to transfer the
exceptions into a uniformly API-response-structure with all necessary information, so that the user can deal with this
error response in an appropriate way. At the moment, our ExceptionInterceptor would return "Internal Server Error. File
not found"... this is not really helpful.
Although we have a corresponding HTTP-statuscode in our mappers (404 for NotFound, 415 for UnsupportedMediaType ...),
this is not fine-grained enough for a real business application.
For that, we define our response structure, which we like to return. We want to provide the following information:

* HTTP-Status 
* business error code
* business error message (localized)

The error-object could be defined the following way (we use JAXB-entities for flexibility, so we can provide a response
in XML or JSON out of the box):
 
```java
import javax.ws.rs.core.Response;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Locale;
import java.util.ResourceBundle;
 
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(propOrder={"status", "errorCode", "message"})
public class APIErrorResponse {
 
    @XmlJavaTypeAdapter(ResponseStatusAdapter.class)
    private Response.Status status;
    private String errorCode;
    private String message;
 
    public APIErrorResponse() {}
 
    public APIErrorResponse(APIError apiError, Locale locale) {
        this.status = apiError.getStatus();
        this.errorCode = apiError.getErrorCode();
        this.message = getLocalizedMessage(apiError, locale);
    }
 
    public APIErrorResponse(Exception exception, Locale locale) {
        this.status = Response.Status.INTERNAL_SERVER_ERROR;
        this.errorCode = "0";
        this.message = exception.getLocalizedMessage();
    }
 
    public APIErrorResponse(Response.Status status,
                            String errorCode,
                            String messageKey,
                            Locale locale) {
        this.status = status;
        this.errorCode = errorCode;
        this.message = getLocalizedMessage(messageKey, locale);
    }
 
 
    public String getErrorCode() {
        return this.errorCode;
    }
 
    public Response.Status getStatus() {
        return status;
    }
 
    public String getMessage() {
        return this.message;
    }
 
 
    private String getLocalizedMessage(APIError apiError,
                                       Locale locale) {
        ResourceBundle resourceBundle =
                ResourceBundle.getBundle(apiError.getClass().getName(), locale);
        return resourceBundle.getString(apiError.getMessageKey());
    }
 
    private String getLocalizedMessage(String messageKey,
                                       Locale locale) {
        ResourceBundle resourceBundle =
                ResourceBundle.getBundle(getClass().getName(), locale);
        return resourceBundle.getString(messageKey);
    }
 
}
```

**Note:** What's behind `APIError` is discussed in a second.  
  
  
The `ResponseStatusAdapter` only converts the `javax.ws.rs.core.Response.Status` at the point of serializing the
HTTP-response into a String:

```java
import javax.ws.rs.core.Response;
import javax.xml.bind.annotation.adapters.XmlAdapter;
 
public class ResponseStatusAdapter extends XmlAdapter<String, Response.Status> {
 
    @Override
    public String marshal(Response.Status status) throws Exception {
        return status.name();
    }
 
    @Override
    public Response.Status unmarshal(String statusAsString) throws Exception {
        return Response.Status.valueOf(statusAsString);
    }
 
}
```

**Note:** For the mehod `getLocalizedMessage()` in class `APIErrorResponse` we need corresponding Properties-files. For
this purpose, however, we come back later. 

 

Next, we want to think about, how we can transform all caught exceptions and all error situations, where we need to
generate our own exceptions to this generic response structure, which we defined above. In addition, we want the
business code from our business domain to know nearly nothing about this technical structure.

We want to encapsulate all technical error information and error messages. For that, an ENUM structure would be ideal.
This ENUM could have the following structure:

```java
import javax.ws.rs.core.Response;
 
public enum APIUserError {
 
    U10001(Response.Status.BAD_REQUEST, "no_valid_username"),
 
    U10002(Response.Status.NOT_FOUND, "username_not_found");
 
 
    private Response.Status status;
 
    private String messageKey;
 
 
    APIUserError(Response.Status status, String messageKey) {
        this.status = status;
        this.messageKey = messageKey;
    }
 
}
```

Of course, wen can provide all errors in this one ENUM, but in bigger projects with several different business error
situations, this becomes unusable. Furthermore, we want the "User-error-codes" in the users domain and the
"accounting-error-codes" in the accounting domain (this is important in a domain-driven-design).

It is very important, that all Error-ENUMs have the same structure, so that they can be used in the same way. In order
to reach this goal, we define an interface:

```java 
import javax.ws.rs.core.Response;
 
public interface APIError {
 
    Response.Status getStatus();
 
    String getErrorCode();
 
    String getMessageKey();
 
}
```
 
And now, we let all Error-ENUM implement exactly this interface: 
 
 
```java
import javax.ws.rs.core.Response;
 
public enum APIUserError implements APIError {
 
    U10001(Response.Status.BAD_REQUEST, "no_valid_username"),
 
    U10002(Response.Status.NOT_FOUND, "username_not_found");
 
 
    private Response.Status status;
 
    private String messageKey;
 
 
    APIUserError(Response.Status status, String messageKey) {
        this.status = status;
        this.messageKey = messageKey;
    }
 
 
    @Override
    public Response.Status getStatus() {
        return this.status;
    }
 
    @Override
    public String getErrorCode() {
        return this.name();
    }
 
    @Override
    public String getMessageKey() {
        return this.messageKey;
    }
}
```
 
Now, we can put the concrete error ENUMs into the corresponding business domain. So, for example, we have an
APIUserError in the user-package and an APIAccountError in the accounting-package and so on.

Now, let's go back to our Properties-files for the localized error messages. We create two files here for the german and
the english messages (`APIUserError_de.properties`, `APIUserError_en.properties`). The files are created in the same
package as `APIUserError`. The file content is the well-known key-value-structure:

 
```properties
APIUserError_de.properties:  


no_valid_username=Der \u00fcbergebene Benutzername ist ung\u00fcltig
```

```properties
APIUserError_en.properties


no_valid_username=The provided username is invalid
```


If we now look back again at our `APIErrorResponse` class, we will see the 'trick':  
Because all error-ENUMs implement the `APIError`-interface, they all can be generically given as parameter in the
constructor of `APIErrorResponse`. The additional parameter 'locale' controls the creation of the correct localized
error-message.  
**Note:** The current locale for this parameter can be determined from an ApplicationContext.
 

Ok, but one piece of the puzzle is still missing. We do not want to handle each exception separately, furthermore we
need to throw our own exceptions in suitable situations. So we can recap, which situations can occur:
 
* we have a concrete error situation in our business domain (e.g. "Username not found") and we must inform the users of
  our API about it in the HTTP response
* there is an exception from code of a third library
* we have some 'unclear' situation, mostly a technical problem like an `IOException`, and we want to provide at least a
  proper error message and not an HTML-error-page from the webserver
 

In order to get a consistent exception handling within our API, we need a consistent exception class. This exception
class should handle at least the three error situations mentioned before:

```java
import javax.ws.rs.core.Response; import java.util.Locale;
 
public class APIException extends RuntimeException {
 
    public static final String HTTP_HEADER_X_ERROR = "X-Error";
    public static final String HTTP_HEADER_X_ERROR_CODE = "X-Error-Code";
 
 
    private Response httpResponse;
 
 
    public APIException(APIError apiError, Locale locale) {
        httpResponse = createHttpResponse(new APIErrorResponse(apiError, locale));
    }
 
    public APIException(Exception exception, Locale locale) {
        httpResponse = createHttpResponse(new APIErrorResponse(exception, locale));
    }
 
    public APIException(Response.Status status,
                        String errorCode,
                        String messageKey,
                        Locale locale) {
        new APIErrorResponse(status, errorCode, messageKey, locale);
    }
 
 
    public Response getHttpResponse() {
        return httpResponse;
    }
 
 
    private static Response createHttpResponse(APIErrorResponse response) {
        return Response.status(response.getStatus()).entity(response)
                .header(HTTP_HEADER_X_ERROR, response.getMessage())
                .header(HTTP_HEADER_X_ERROR_CODE, response.getErrorCode()).build();
    }
 
}
```    
  
The main important facts of this `APIException` are:

* the `APIException` class inherits from `RuntimeException` so that we do not have to deal with checked exceptions or
  have to provide this technical exception in the 'throws clause' of the method signatures
* each constructor of the class represents one of the above error situations
 

Ok, now we have to extend the handling of exceptions within our ExceptionInterceptor: 

```java
import javax.inject.Inject;
import javax.inject.Named;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import javax.ws.rs.core.Response;
import java.util.Locale;
 
@Interceptor
public class APIExceptionInterceptor {
 
    @Inject
    Locale locale;
 
    @AroundInvoke
    public Object handleException(InvocationContext context) {
        Object proceedResponse;
        try {
            proceedResponse = context.proceed();
        } catch (Exception ex) {
            Response errorResponse;
            if (ex instanceof APIException) {
                errorResponse = ((APIException) ex).getHttpResponse();
            } else if (ex.getCause() instanceof APIException) {
                errorResponse = ((APIException) ex.getCause()).getHttpResponse();
            } else {
                errorResponse = new APIException(ex, locale).getHttpResponse();
            }
            return errorResponse;
        }
        return proceedResponse;
    }
}
```

**Note:** The property `java.util.Locale`is provided by a producer, so it can be injected here very easy (see
`@Produces`).

Want is going on here now? We check in the catch-clause, if we have an `APIException` and if so, we can immediately
return its HTTP-Response. It could be the case, that the APIException is wrapped within another exception, so we check
this situation as well.  
If there was thrown another exception, this exception is transformed into the `APIException` (in the second else-case). 

In the following example, we want to generate a business error like 'Username not found':

```java
@Stateless
public class UserRepository {
 
    @PersistenceContext
    EntityManager entityManager;
 
    @Inject
    Locale locale;
 
    public UserRepository() {}
 
    public User getByUsername(String username) {
        User user = entityManager.find(User.class, username);
        if (user != null) {
            return user;
        }
        throw new APIException(APIUserError.U10002, locale);
    }
 
}
```
 
As seen here, it is very easy to create a localized exception with business error messages. The business code is not
polluted with technical aspects (this business code does not need to have any knowledge, that it is executed in a
REST-environment and that there have to be filled special properties of an error structure). These aspects are hidden
and encapsulated in the APIException and the APIError-ENUM.


### Milestone 2
We have now constructed our central exception handling. In order to extend it, the only thing to do is to extend the
`APIError`-ENUM and the localized error messages in the properties files. Because the `APIError`-ENUMs are in the
corresponding domain-packages, we stay in the business domain even with the exception handling.



## Integration of BeanValidation
In a REST API, we always need some kind of validation of the the provided properties. This could be the check for
mandatory fields or the validation of the dataformat of a property (this is very important especially for date/time
formats) or the format of an eMail-address. There are plenty of situations for validation.

Such checks are mainly business-checks or better, they are defined by business requirements. For example, a birthdate
ist mostly modelled with `java.util.Date`, but it needs only the date part and no hour, minutes or seconds. Or, if some
field is mandatory, that is defined only by business requirements... you don't see at the pure class structure, if some
age-field must be provided or not.

So, we would not maintain such checks and validations in our technical REST-API layer. It would be better to provide
these rules directly at the domain objects. Perhaps, these validations are already present at the domain objects in the
form of BeanValidation-annotations.  
A typical domain object could be modelled like this:

```java
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
 
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class User {
 
    @NotNull
    @Size(min = 2, max = 40)
    private String username;
 
    @NotNull
    @Pattern(regexp = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")
    private String email;
 
 
    public UserDTO() {
    }
 
    // evtl. getter und setter
 }
```

We expect this domain object as parameter for our UsersResource in the HTTP-request:

```java
@POST public Response registerUser(User userRequest) {
    User managedUser = userRepository.register(userRequest);
    URI uri = super.info.getAbsolutePathBuilder()
        .path("/" + managedUser.getEmail()).build();
    return Response.created(uri).entity(managedUser).build();
}
```
 
Now, we have two possibilities to apply the BeanValidation on our User-object:

* @Valid-Annotation
* programmatically
    

The first possibility is to put the `@javax.validation.Valid`-annotation directly in front of the method parameter. In
this case, the BeanValidation is called on the User-object right after deserializing of the HTTP-payloads. The two
properties are then validated against the rules provided in the annotation (here the @NotNull, @Size and @Pattern-rules):

```java 
@POST
public Response registerUser(@Valid User userRequest) {
    // ...
}
``` 


The second possibility, namely invoking the BeanValidation programmatically, needs a bit more code, but is more flexible:

```java
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
 
public class ValidationController {
 
    // ...
 
    public static <T> void processBeanValidation(T entity) {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        Validator validator = factory.getValidator();
        Set<ConstraintViolation<T>> errors = validator.validate(entity);
        if (!errors.isEmpty()) {
            throw new ConstraintViolationException(errors);
        }
    }
 
}
```
 
In our `registerUser()`-method, we would invoke the validation with: 

```java
@POST
public Response registerUser(User userRequest) {
    // ...
    ValidationController.processBeanValidation(user);
}
```
 
It depends on many aspects, which approach is finally chosen. With the programmatic way, you are overall more flexible.
But for simple entities and use-cases, the @Valid-annotation is already enough.
 
Now comes the exciting question: How do we combine our central exception handling with the construct of BeanValidation?
For that, we need to dive little deeper into the implementation of the BeanValidation. There, we will find the fact,
that there is thrown a `javax.validation.ConstraintViolationException`, if the validating rules (NotNull, Size and so
on) are violated.  
So, we can use an ExceptionMapper for this specific exception:

```java
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Variant;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
 
@Provider
public class ConstraintViolationMapper
                        implements ExceptionMapper<ConstraintViolationException> {
 
    private static List<Variant> acceptableMediaTypes =
            Variant.mediaTypes(MediaType.APPLICATION_JSON_TYPE,
                               MediaType.APPLICATION_XML_TYPE).build();
 
    @Context
    protected Request request;
 
 
    @Override
    public Response toResponse(ConstraintViolationException ex) {
        Set<ConstraintViolation<?>> constViolations = ex.getConstraintViolations();
        List<ConstraintViolationEntry> errorList = new ArrayList<>();
        for (ConstraintViolation<?> constraintViolation : constViolations) {
            errorList.add(new ConstraintViolationEntry(constraintViolation));
        }
        GenericEntity<List<ConstraintViolationEntry>> entity =
                new GenericEntity<List<ConstraintViolationEntry>>(errorList) {};
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(entity).type(getNegotiatedMediaType()).build();
    }
 
    protected MediaType getNegotiatedMediaType() {
        final Variant selectedMediaType = request.selectVariant(acceptableMediaTypes);
        if (selectedMediaType == null) {
            return MediaType.APPLICATION_JSON_TYPE;
        }
        return selectedMediaType.getMediaType();
    }
 
}
```

**Note:** The code around the `getNegotiatedMediaType()`-method can of course be outsourced. For simplicity, I listed it
here. The key-fact here is, that the HTTP-response type is determined from the MediaType of the HTTP-request. This means
that the response structure is always returned in the format that the client has supplied in its initial request.


A `ConstraintViolationException` always contains all occurring validation errors. So in the validation process, all
validations are processed first and then all violation errors are returned in a set of violations of the single
`ConstraintViolationException`.  
Now, we want to return all violations to the user in one response-structure. For that, we transform every single
ConstraintViolation in a new structure and return the complete violation-list as one entity as HTTP-response:

```java
import javax.validation.ConstraintViolation;
import javax.validation.Path;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.Iterator;
 
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ConstraintViolationEntry {
 
    private String fieldName;
    private String wrongValue;
    private String errorMessage;
 
    public ConstraintViolationEntry() {}
 
    public ConstraintViolationEntry(ConstraintViolation violation) {
        Iterator<Path.Node> iterator = violation.getPropertyPath().iterator();
        Path.Node currentNode = iterator.next();
        String invalidValue = "";
        if (violation.getInvalidValue() != null) {
            invalidValue = violation.getInvalidValue().toString();
        }
        this.fieldName = currentNode.getName();
        this.wrongValue = invalidValue;
        this.errorMessage = violation.getMessage();
    }
 
    public String getFieldName() {
        return fieldName;
    }
 
    public String getWrongValue() {
        return wrongValue;
    }
 
    public String getErrorMessage() {
        return errorMessage;
    }
 
}
```
 
However, in this case, the ExceptionInterceptor and the ConstraitViolationMapper interfere each other. Or other way
round: The ExceptionInterceptor catches the exception first, before the ConstraintViolationMapper can process the
exception.  
For this reason, we need to enhance our ExceptionInterceptor a little bit:

```java
import javax.inject.Inject;
import javax.inject.Named;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import javax.validation.ConstraintViolationException;
import javax.ws.rs.core.Response;
import java.util.Locale;
 
@Named
@Interceptor
public class RESTExceptionInterceptor {
 
    @Inject
    Locale locale;
 
    @AroundInvoke
    public Object handleException(InvocationContext context) {
        Object proceedResponse;
        try {
            proceedResponse = context.proceed();
        } catch (Exception ex) {
            Response errorResponse;
            if (ex instanceof APIException) {
                errorResponse = ((APIException) ex).getHttpResponse();
            } else if (ex.getCause() instanceof APIException) {
                errorResponse = ((APIException) ex.getCause()).getHttpResponse();
            } else if (ex.getCause() instanceof ConstraintViolationException) {
                throw (ConstraintViolationException) ex.getCause();
                // ---> this exception is handled via the ConstraintViolationMapper
            } else {
                errorResponse = new APIException(ex, locale).getHttpResponse();
            }
            return errorResponse;
        }
        return proceedResponse;
    }
}
```

The important part here is the additional "else if"-branch for the `ConstraintViolationException`. We extract the cause
of the caught exception, which is our `ConstraintViolationException` and **rethrow** exactly this
`ConstraintViolationException`. Now, the `ConstraintViolationMapper` can catch and handle the exception.

 
## Summary
We now have implemented a little framework, with which we can centralize the API-exception handling. An API-client
always can rely on a uniform error structure, and even he gets the localized error messages.  
In addition, all the exceptions, which are produced by BeanValidation, are also automatically handled and are
transformed to our uniform error structure. That means, we do not need to implement something special to handle
exceptions from BeanValidation and so we can focus on the business domain code.

The only maintenance required here is the extending of the `APIError`-ENUMs and the translating of the error message
within the Properties-files. If we need to throw some exception, we can use the `APIException`and and fill them with the
appropriate `APIError`-ENUM. 

As mentioned earlier and as a possible outlook for increasing optimization, the ExceptionInterceptor can be used via
Interceptor-Binding (http://docs.oracle.com/javaee/7/api/javax/interceptor/InterceptorBinding.html) instead of the
`@Interceptor`annotations.  
In addition, we can think about using readable error-constants like NO_USER_FOUND instead of the more technical one we
used currently (U10002).
