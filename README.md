# Spring Security y JWT - Proyecto plantilla

Este proyecto lo realizaré como una plantilla para poder reutilizarlo en futuros proyectos que requieran usar JWT como
medio de autenticación. Es decir, crearé una carpeta **security** que contendrá toda la configuración de seguridad, a
fin de solo copiar y pegar esta carpeta en el nuevo proyecto.
---

# Capa de Negocio

Para poder utilizar Spring Security necesitamos "algo" a lo que le daremos seguridad. Ese algo será nuestra aplicación
de negocio, donde expondremos ciertos endpoints (un crud básico) que más adelante, según el authority del usuario
podrán ser accedidos.

## Dependencias

Para la construcción de la aplicación de negocio usaremos las siguientes dependencias:

````xml

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
        <groupId>com.mysql</groupId>
        <artifactId>mysql-connector-j</artifactId>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
````

Recordar que estamos trabajando con ``java 17 y Spring Boot 3.1.1``.

## Configurando DataSource

Nuestro **application.properties** tendrá las siguientes configuraciones:

````properties
# Datasource
spring.datasource.url=jdbc:mysql://localhost:3306/db_spring_security_jwt_template_project?serverTimezone=America/Lima
spring.datasource.username=root
spring.datasource.password=magadiflo
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
# Jpa
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true
spring.jpa.database=mysql
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQLDialect
````

## Entidad del negocio

Crearemos una entidad **Product** para el que crearemos su crud:

````java

@Entity
@Table(name = "products")
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private Double price;

    /* omitted setters, getters and toString() method */
}
````

## Repositorio de la entidad del negocio

````java
public interface ProductRepository extends JpaRepository<Product, Long> {
}
````

## Capa de servicio

Crearemos una interfaz por buenas prácticas y la implementación del mismo:

````java
public interface ProductService {
    List<Product> findAllProducts();

    Optional<Product> findProductById(Long id);

    Product saveProduct(Product product);

    Optional<Product> updateProduct(Long id, Product product);

    Optional<Boolean> deleteProduct(Long id);
}
````

Hacemos inyección de dependencia de nuestro repositorio para poder hacer las operaciones hacia la base de datos.

````java

@Service
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;

    public ProductServiceImpl(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public List<Product> findAllProducts() {
        return this.productRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Product> findProductById(Long id) {
        return this.productRepository.findById(id);
    }

    @Override
    @Transactional
    public Product saveProduct(Product product) {
        return this.productRepository.save(product);
    }

    @Override
    @Transactional
    public Optional<Product> updateProduct(Long id, Product product) {
        return this.productRepository.findById(id)
                .map(productDB -> {
                    productDB.setName(product.getName());
                    productDB.setPrice(product.getPrice());
                    return this.productRepository.save(productDB);
                });
    }

    @Override
    @Transactional
    public Optional<Boolean> deleteProduct(Long id) {
        return this.productRepository.findById(id)
                .map(productDB -> {
                    this.productRepository.deleteById(productDB.getId());
                    return true;
                });
    }
}
````

## Rest Controller Product

Los endpoints que exponen las operaciones CRUD. Hacemos inyección de dependencia de nuestra capa de servicio.

````java

@RestController
@RequestMapping(path = "/api/v1/products")
public class ProductController {
    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping
    public ResponseEntity<List<Product>> getAllProducts() {
        return ResponseEntity.ok(this.productService.findAllProducts());
    }

    @GetMapping(path = "/{id}")
    public ResponseEntity<Product> getProduct(@PathVariable Long id) {
        return this.productService.findProductById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<Product> saveProduct(@RequestBody Product product) {
        Product productDB = this.productService.saveProduct(product);
        URI productURI = URI.create("/api/v1/products/" + productDB.getId());
        return ResponseEntity.created(productURI).body(productDB);
    }

    @PutMapping(path = "/{id}")
    public ResponseEntity<Product> updateProduct(@PathVariable Long id, @RequestBody Product product) {
        return this.productService.updateProduct(id, product)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping(path = "/{id}")
    public ResponseEntity<?> deleteProduct(@PathVariable Long id) {
        return this.productService.deleteProduct(id)
                .map(isRemoved -> ResponseEntity.noContent().build())
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
````

## Probando endpoints

Se muestran los 5 endpoints expuestos por nuestra API. Aquí hacemos pruebas **sin tener Spring Security.**

### Listar todos los productos

````bash
curl -i http://localhost:8080/api/v1/products
HTTP/1.1 200
Content-Type: application/json
Transfer-Encoding: chunked
Date: Tue, 27 Jun 2023 15:55:45 GMT

[
  {"id":1,"name":"Pc gamer","price":3500.0},
  {"id":2,"name":"Teclado inalámbrico","price":150.8},
  {"id":3,"name":"Mouse inalámbrico","price":99.9},
  {"id":4,"name":"Celular Samsung A7","price":5900.0}
]
````

### Ver un producto

Producto existente con id = 3:

````bash
curl -i http://localhost:8080/api/v1/products/3
HTTP/1.1 200
Content-Type: application/json
Transfer-Encoding: chunked
Date: Tue, 27 Jun 2023 15:57:30 GMT

{"id":3,"name":"Mouse inalámbrico","price":99.9}
````

Producto no existente con id = 50

````bash
curl -i http://localhost:8080/api/v1/products/50
HTTP/1.1 404
Content-Length: 0
Date: Tue, 27 Jun 2023 16:04:16 GMT
````

### Guardar un producto

````bash
curl -i -X POST -H "Content-Type: application/json" -d "{\"name\": \"Monitor LG 27'\", \"price\": 780.50}" http://localhost:8080/api/v1/products
HTTP/1.1 201
Location: /api/v1/products/5
Content-Type: application/json
Transfer-Encoding: chunked
Date: Tue, 27 Jun 2023 15:59:40 GMT

{"id":5,"name":"Monitor LG 27'","price":780.5}
````

### Actualizar un producto

Actualizar producto existente con id = 5:

````bash
curl -i -X PUT -H "Content-Type: application/json" -d "{\"name\": \"Monitor LG 32' Ultra HD\", \"price\": 1200.00}" http://localhost:8080/api/v1/products/5
HTTP/1.1 200
Content-Type: application/json
Transfer-Encoding: chunked
Date: Tue, 27 Jun 2023 16:01:54 GMT

{"id":5,"name":"Monitor LG 32' Ultra HD","price":1200.0}
````

Actualizar producto no existente con id = 60:

````bash
curl -i -X PUT -H "Content-Type: application/json" -d "{\"name\": \"Parlantes chicos\", \"price\": 48}" http://localhost:8080/api/v1/products/60
HTTP/1.1 404
Content-Length: 0
Date: Tue, 27 Jun 2023 16:07:07 GMT
````

### Eliminar un producto

Eliminando producto existente con id = 5:

````bash
curl -i -X DELETE http://localhost:8080/api/v1/products/5
HTTP/1.1 204
Date: Tue, 27 Jun 2023 16:03:05 GMT
````

Eliminando producto no existente con id = 74:

````bash
curl -i -X DELETE http://localhost:8080/api/v1/products/74
HTTP/1.1 404
Content-Length: 0
Date: Tue, 27 Jun 2023 16:07:49 GMT
````

---

# Spring Security con JWT

A partir de esta sección iniciamos el desarrollo del proyecto como plantilla usando JWT con Spring Security.

## Nuevas dependencias

Existen muchas librerías que nos ayudan a crear, firmar, verificar, etc. un JWT. Vi en muchos
tutoriales que he realizado, el uso de dos de ellas con mayor frecuencia: [**jwtk/jjwt**](https://github.com/jwtk/jjwt)
y el [**auth0/java-jwt**](https://github.com/auth0/java-jwt). En nuestro caso, optaré por usar la segunda librería
**(auth0/java-jwt),** ya que según lo investigado es más robusto que el otro que es un poco más liviano.

````xml

<dependencies>
    <!--Dependencias para Spring Security-->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>

    <!--Dependencia de auth0/java-jwt para trabajar con JWT-->
    <dependency>
        <groupId>com.auth0</groupId>
        <artifactId>java-jwt</artifactId>
        <version>4.4.0</version>
    </dependency>
</dependencies>
````

## Comportamiento por defecto

Tan solo agregando la dependencia de **Spring Security**, basta para tener nuestra aplicación asegurada por defecto. Es
decir, para poder acceder a algún endpoint, necesito autenticarme. Por defecto, Spring Security agrega el
**Http Basic Authentication** y el **Form Login Authentication**, esto significa que, al acceder con **curl** o
**postman** se hará uso del **Http Basic Authentication**, mientras que si accedemos usando un navegador web, se
activará el filtro de **Form Login Authentication**.

A continuación se muestran los ejemplos:

Accediendo a la lista de productos usando curl. Tenemos que agregar el usuario **user** y la contraseña generada de
aleatoriamente en la consola:

````bash
curl -i -u user:01f90fdc-9566-4694-a3cc-cd8a2855f0f2 http://localhost:8080/api/v1/products
HTTP/1.1 200
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Tue, 27 Jun 2023 21:47:20 GMT

[ 
  {"id":1,"name":"Pc gamer","price":3500.0},
  {"id":2,"name":"Teclado inalámbrico","price":150.8},
  {"id":3,"name":"Mouse inalámbrico","price":99.9},
  {"id":4,"name":"Celular Samsung A7","price":5900.0}
]
````

Accediendo a la lista de productos usando el navegador web. Al hacerlo veremos que nos redireccionará a un formulario
de Login para poder ingresar el usuario **user** y la contraseña generada aleatoriamente en la consola. Luego de
ingresar las credenciales e iniciar sesión, nos redirecciona a la ruta que solicitamos inicialmente:

````
http://localhost:8080/api/v1/products?continue
````

````json
[
  {
    "id": 1,
    "name": "Pc gamer",
    "price": 3500
  },
  {
    "id": 2,
    "name": "Teclado inalámbrico",
    "price": 150.8
  },
  {
    "id": 3,
    "name": "Mouse inalámbrico",
    "price": 99.9
  },
  {
    "id": 4,
    "name": "Celular Samsung A7",
    "price": 5900
  }
]
````

## Componentes principales que actúan en el proceso de Autenticación y Authorización en Spring Security

A modo de repaso general, es importante tener conocimiento del siguiente esquema donde muestra los componentes
principales que actúan en el proceso de autenticación en Spring Security obtenido del libro de
[**Spring Security In Action 2020**](https://github.com/magadiflo/spring-security-in-action-2020.git)

![Main-components-authentication-spring-security](./assets/01.Main-components-authentication-spring-security.png)

Después de una autenticación exitosa, el **Authentication Filter** almacena los detalles del usuario en el **Security
context** y reenvía la solicitud al **Authorization Filter**. El filtro de autorización decide si se permite la llamada.
Para decidir si autorizar la solicitud, el **Authorization Filter** utiliza los detalles del contexto de seguridad.

![Flow-authorization](./assets/02.Flow-authorization.png)

Las imágenes mostradas anteriormente serán tomadas como referencia al momento de ir construyendo el proyecto de
seguridad con JWT.

## Creando la Entity User

Creamos nuestra entidad **User** que será la que mapearemos con la tabla **users** de la base de datos.

````java

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstName;
    private String lastName;
    private String username;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;

    /* omitted setters and getters */
}
````

El rol y las authorities dependerán de la lógica de negocio al que se esté aplicando. Así pues, en este proyecto
**trabajaremos solo con roles**, en tal sentido, un usuario tendrá asignado un único rol.

````java
public enum Role {
    USER, ADMIN, SUPER_ADMIN
}
````

**NOTA**
> Recordar que roles y authorities son dos cosas distintas. Digamos que Roles es más amplio y contienen authorities.
> Además, a los authorities se les conoce como permisos. En ese sentido, un rol puede tener muchos authorities o
> permisos.

## Repositorio para User

Creamos el repositorio de User para hacer consultas a la base de datos. Además, definimos un método personalizado que
nos retornará un User en función de su username:

````java
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findUserByUsername(String username);
}
````

## Creación de usuarios con roles

Para no estar registrando manualmente los usuarios que utilizaremos en el sistema, agregaré las instrucciones en el
**import.sql** para que se agreguen cada vez que iniciemos la aplicación. Como se observa, tendremos tres usuarios,
para poder probar los tres roles que creamos, además, notar que el password ya se encuentra hasheado, el valor
original es **12345** para los tres.

````
INSERT INTO users(first_name, last_name, username, password, role) VALUES('Martín', 'Díaz', 'martin', '$2a$10$jI7KjaUItqfNp.3RHRTCTOlglEwd5YWYlY/klOYccx/wWZpcrPrmO', 'SUPER_ADMIN');
INSERT INTO users(first_name, last_name, username, password, role) VALUES('Elizabeth', 'Tello', 'eli', '$2a$10$b7Fkn.Rm36pw7LojoRKQuOUF.elMZYm6ScR6TciKuqc1pj8XpW9Fa', 'ADMIN');
INSERT INTO users(first_name, last_name, username, password, role) VALUES('Nuria', 'Corneio', 'nuria', '$2a$10$UVX62X4pPzpIBYaCC28EpuQMbVuRVaYyFStb2bhVrC3L.TNdsJhf.', 'USER');
````

## Creando usuario reconocido en la arquitectura de Spring Security

Anteriormente, creamos nuestra entity **User** para mapear los registros de usuarios con la base de datos y hacer
operaciones con él, es decir, esta entity User representa la entidad de negocio que estemos trabajando. Por otro lado,
Spring Security define un usuario propio, es decir, **un usuario que es reconocido dentro de su arquitectura** con el
que se trabajará la autenticación y autorización en la aplicación. Entonces, crearemos este modelo de usuario propio de
Spring Security al que le asociaremos nuestra entity User, de esta forma estamos separando las responsabilidades,
por un lado, tenemos la Entity User propio del negocio, y, por otro lado, tenemos un usuario propio de Spring Security
al que le llamaremos **SecurityUser**:

````java
public class SecurityUser implements UserDetails {

    private final User user;

    public SecurityUser(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + this.user.getRole().name()));
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
````

**NOTA**
> Nuestro modelo de usuario SecurityUser es un usuario reconocido dentro de la arquitectura de Spring Security y eso es
> porque hace una implementación de la interfaz **UserDetails**.
>
> El método getAuthorities() nos retorna una lita de Authorities o Roles o la mezcla de ambos, es decir, en este punto
> Spring Security no hace una distinción y trata a ambos como authorities, entonces, **¿dónde se ve la diferencia?**,
> esta diferencia radica cuando se aseguran los métodos ya sea usando **hasAuthority(...) o hasAnyAuthority(...)** en
> donde aquí se usarán los authorities o permisos definidos en nuestra lista, y si los métodos se aseguran con
> **hasRole(...) o con hasAnyRole(...)** aquí se usarán los roles definidos en nuestra lista.
>
> Es importante, cuando definamos en la lista del método **getAuthorities()** nuestros roles tengan el prefijo "ROLE_",
> mientras que los authorities se usan tal cual lo estemos definiendo, por ejemplo, aunque no es nuestro caso, ya que
> solo estamos trabajando con roles, podríamos haber definido nuestros authorities de la siguiente manera: **user:read,
> user:write, admin:write, admin:read, delete, read, write, update, etc**, la forma cómo definamos nuestros authorities
> o permisos ya depende de nosotros.

## Creando implementación del UserDetailsService y PasswordEncoder

Crearemos una clase de servicio que implemente la interfaz **UserDetailsService** y lo anotaremos con **@Service** para
que se convierta en un **bean** manejado por el contenedor de Spring.

````java

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userRepository.findUserByUsername(username)
                .map(SecurityUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("Username no encontrado en la BD!"));
    }
}
````

Nuestra clase UserDetailsServiceImpl implementa a **UserDetailsService**, y con él su método **loadUserByUsername()**,
que nos devolverá una implementación de un usuario reconocido en la arquitectura de Spring Security, un **UserDetails**
cuya implementación la definimos en la sección anterior, el **SecurityUser**, caso contrario nos lanzará la excepción
**UsernameNotFoundException**.

Con respecto al **PasswordEncoder**, creamos una clase de configuración general para exponer beans relacionados a la
configuración de Spring Security, en este caso, para el **PasswordEncoder** creamos un método que nos devuelve un
**BCryptPasswordEncoder** como implementación del **PasswordEncoder**:

````java

@Configuration
public class SecurityConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
````

## Testeando la aplicación hasta este punto

Hasta el momento hemos creado una implementación del **UserDetailsService** y del **PasswordEncoder**, también del
**UserDetails**, pero enfoquémonos en el **UserDetailsService y PasswordEncoder** que son dos elementos importantes
para poder explicar el flujo en el proceso de Autenticación.

Como vimos, por defecto, cuando agregamos la dependencia de Spring Security, nuestra aplicación queda asegurada usando
**HTTP Basic Authentication y Form Login Authentication**, además vimos cuáles son los componentes que interactúan en
el flujo del proceso de Authentication en Spring Security **(ver diagrama)**. Dos de esos componentes son el
**UserDetailsService y el PasswordEncoder** que son utilizados por la implementación del **AuthenticationProvider**
para realizar la lógica de autenticación.

Cuando creamos nuestra implementación del **UserDetailsService** sobreescribimos la implementación
que por defecto viene en Spring Security, eso significa que ahora **en consola no nos mostrará un password aleatorio**,
ni el usuario por defecto será **user**, sino que ahora, al definir nuestra propia implementación del
**UserDetailsService** cogeremos los usuarios de la base de datos. Además, al sobreescribir el **UserDetailsService**
que viene por defecto, dejamos anulado el **PasswordEncoder** usado en esa implementación, eso significa que debemos
crear una implementación de un **PasswordEncoder** y registrarlo como un bean, ya que de lo contrario, si solo
sobreescribimos la implementación por defecto del UserDetailsService sin crear una implementación de un PasswordEncoder
la aplicación nos arrojará el siguiente error:

````
java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
````

El error anterior significa que **no hay una implementación de un PasswordEncoder**. Por lo tanto, cuando creemos
nuestra propia implementación del **UserDetailsService** del mismo modo debemos crear la implementación del
**PasswordEncoder**

En este proyecto estoy usando una clase que implementa el UserDetailsService y lo estoy anotando con **@Service** para
que sea manejado por el contenedor de Spring, aunque también podría haberlo creado anotando un método con **@Bean** y
retornando una implementación del UserDetailsService, tal como se vino realizando en el libro de **Spring Security In
Action 2020**, aunque en el libro también se vio la implementación del UserDetailsService a través de una clase anotada
con **@Service**.

Con el **usuario de la base de datos** definido en el archivo **import.sql** vemos el detalle de un producto:

````bash
curl -i -u martin:12345 http://localhost:8080/api/v1/products/1
HTTP/1.1 200
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Wed, 28 Jun 2023 16:35:23 GMT

{"id":1,"name":"Pc gamer","price":3500.0}
````

Si no le mandamos ningún usuario:

````bash
curl -i http://localhost:8080/api/v1/products/1
HTTP/1.1 401
Set-Cookie: JSESSIONID=126880F8CB33106D3ACF3DED5C34CB22; Path=/; HttpOnly
WWW-Authenticate: Basic realm="Realm"
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
WWW-Authenticate: Basic realm="Realm"
Content-Length: 0
Date: Wed, 28 Jun 2023 16:38:22 GMT
````

## Creando el JwtTokenProvider

El **JwtTokenProvider** será una clase de componente que utilizará la librería **auth0/java-jwt** para proveernos
el **access token** y todo lo relacionado a él: validación, obtención de los claims, etc., es decir será como nuestra
clase **Fachada** a partir del cual podemos obtener todo lo relacionado con el access token.

````java

@Component
public class JwtTokenProvider {
    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final long EXPIRATION_TIME = 30 * 60 * 1000; //30min
    private static final String AUTHORITIES = "authorities";
    private static final String ISSUER = "Magadiflo Company";
    private static final String AUTHORIZATION = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";
    @Value("${jwt.secret.key}")
    private String jwtSecretKey;
    /* omitted code */
}
````

**Donde**

- **EXPIRATION_TIME**, define el tiempo de vida del access token, en nuestro caso es de 30 minutos, pero está expresado
  en milisegundos.
- **AUTHORITIES**, define la key para nuestro claims personalizado que guardará en el token los roles del usuario.
- **ISSUER**, representa el nombre de quien está emitiendo el token, puede ser, por ejemplo el nombre de la compañía a
  la que se le está desarrollando el software.
- **AUTHORIZATION**, el nombre que debe venir en el header trayendo el token.
- **TOKEN_PREFIX**, el header Authorization, debe traer como valor un token con el formato: **bearer [Aquí el token]**
- **jwtSecretKey**, es una variable que obtiene su valor del **application.properties**. A través de la anotación
  **@Value()** se indica la propiedad de la que obtendrá el valor. El valor representa la clave que se usará para poder
  firmar y verificar el access token. En el siguiente fragmento se observa la propiedad en el application.properties:

````properties
jwt.secret.key=[a-zA-Z0-9._]^+$Guidelines.....
````

El método **createAccessToken()** permitirá crear un access token a partir de un **userDetails** usando para eso las
constantes definidas anteriormente.

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    public String createAccessToken(UserDetails userDetails) {
        return JWT.create()
                .withIssuer(ISSUER)
                .withAudience("User", "Managament", "Portal")
                .withIssuedAt(new Date())
                .withSubject(userDetails.getUsername())
                .withClaim(AUTHORITIES, this.authoritiesToCreateAccessToken(userDetails))
                .withExpiresAt(Instant.now().plusMillis(EXPIRATION_TIME))
                .sign(this.getAlgorithm());
    }
    /* omitted code */
}
````

**Donde**

- **withIssuer(ISSUER)**, indica el emisor del token.
- **withAudience("User", "Managament", "Portal")**, cuál es la audiencia a la que va dirigida el token.
- **withIssuedAt(new Date())**, fecha en la que se emite el token.
- **withSubject(userDetails.getUsername())**, definimos un valor único, en nuestro caso definimos el username que es
  único por cada usuario, podríamos haber usado el email, dni, etc., es importante que sea único, ya que lo usaremos más
  adelante para poder identificarlo en la base de datos.
- **withClaim(AUTHORITIES, this.authoritiesToCreateAccessToken(userDetails))**, como necesitamos almacenar nuestra lista
  de authorities o en este caso roles, usamos un **claim personalizado**, es decir, nosotros mismos le definimos la
  clave del claim y su valor, por suerte, tenemos el método **withClaim(...)** que recibe una clave y como valor una
  **lista de String**, también podríamos haber usado el método **withArrayClaim(...)** que a diferencia del anterior
  este recibe un arreglo de String.
- **withExpiresAt(Instant.now().plusMillis(EXPIRATION_TIME))**, le asignamos el tiempo de validez al token a partir del
  momento en que se crea.
- **sign(this.getAlgorithm())**, agregamos el algoritmo para firmar el token.

En el código anterior se hacen uso de dos métodos:

**this.authoritiesToCreateAccessToken(userDetails)**, obtenemos una lista de roles a partir del userDetails:

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    private List<String> authoritiesToCreateAccessToken(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
    /* omitted code */
}
````

**this.getAlgorithm()**, definimos el algoritmo a usar incluyendo nuestra clave para poder firmar o verificar la firma
del token.

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    private Algorithm getAlgorithm() {
        return Algorithm.HMAC512(this.jwtSecretKey.getBytes());
    }
    /* omitted code */
}
````

El siguiente método **isAccessTokenValid()** es muy importante, ya que nos permitirá validar el token que le
proporcionemos retornándonos un valor booleano. Para eso utilizamos un **try-catch**, de tal forma que si ocurre la
excepción (el token no es válido) retornamos **false**, pero si no ocurre ninguna excepción retornamos **true**.

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    public boolean isAccessTokenValid(String token) {
        try {
            this.jwtVerifier().verify(token);
            return true;
        } catch (AlgorithmMismatchException e) {
            LOG.error("El algoritmo del encabezado del token no es igual al del JWTVerifier: {}", e.getMessage());
        } catch (SignatureVerificationException e) {
            LOG.error("La firma no es válida: {}", e.getMessage());
        } catch (TokenExpiredException e) {
            LOG.error("El token ha expirado: {}", e.getMessage());
        } catch (MissingClaimException e) {
            LOG.error("Claim faltante: {}", e.getMessage());
        } catch (IncorrectClaimException e) {
            LOG.error("Claim incorrecto: {}", e.getMessage());
        } catch (JWTVerificationException e) {
            LOG.error("Excepción general de verificación de un JWT: {}", e.getMessage());
        }
        return false;
    }
    /* omitted code */
}
````

Ahora, quien lanza las excepciones si falla la validación, es el método **verify()**. Este método verify() se obtiene
de un **JWTVerifier**. En nuestro caso, definimos un método que nos retorne el **JWTVerifier**, ya que lo usaremos en
dos métodos distintos en este archivo, una, como pudimos ver, es en el método **isAccessTokenValid()** para verificar la
validez del token y el otro método donde se usará es en el **decodedJWT()**.

Como observamos, en el método **jwtVerifier()** configuramos el elemento necesario para que posteriormente se haga la
validación del token. Este elemento es el algoritmo que usamos junto con nuestra clave. Como recordaremos, el método
**getAlgorithm()** es el mismo que explicamos en el apartado superior.

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    private JWTVerifier jwtVerifier() {
        return JWT.require(this.getAlgorithm()).build();
    }
    /* omitted code */
}
````

**Nota**
> Dentro del método **jwtVerifier()** podemos utilizar una configuración adicional agregándole, por ejemplo, el emisor
> (issuer) o el sujeto (subject) para que haga la verificación del token teniendo en cuenta también esas dos
> configuraciones adicionales:
>
> JWT.require(algorithm)**.withIssuer("tu_emisor").withSubject("tu_sujeto")**.build();
>
> Para ejemplificar, podemos tomar como referencia el issuer, supongamos que creamos un token usando además del
> algoritmo el issuer="company". Posteriormente, en la aplicación cambiamos el issuer="society". Ahora, cuando usemos
> el token generado con issuer="company", la validación va a fallar porque ahora el issuer="society".
>
> ``ERROR com.magadiflo.jwt.template.project.app.security.utility.JwtTokenProvider -- Claim incorrecto: The Claim 'iss' value doesn't match the required issuer.``
>
> En nuestro caso, no usaremos dichas configuraciones adicionales, nos basta con usar
> el ``JWT.require(this.getAlgorithm()).build();``

Dijimos que, además del método **isAccessTokenValid()** usamos el método **jwtVerifier()** dentro del método
**decodedJWT()**. Este método, internamente luego de la verificación correcta del token retorna el objeto del tipo
**DecodedJWT** con el que podemos obtener los claims o distintos atributos asignados al crear el token.

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    private DecodedJWT decodedJWT(String token) {
        return this.jwtVerifier().verify(token);
    }
    /* omitted code */
}
````

Con el método **decodedJWT()** del código anterior podemos recuperar el **Subject** a partir del token:

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    public String getSubjectFromAccessToken(String token) {
        return this.decodedJWT(token).getSubject();
    }
    /* omitted code */
}
````

También, usando el método decodedJWT(), podemos recuperar de nuestro token, a partir de nuestro claim personalizado
nuestra lista de authorities. El método siguiente, luego de recuperar los authorities lo transforma para retornar una
lista de GrantedAuthority:

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    public List<GrantedAuthority> getAuthoritiesFromAccessToken(String token) {
        return this.decodedJWT(token).getClaim(AUTHORITIES).asList(String.class).stream()
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
    /* omitted code */
}
````

Finalmente, los siguientes tres métodos están relacionados con el token que se obtiene del **HttpServletRequest**. El
primero recupera el token de la cabecera: "Authorization":

````java

@Component
public class JwtTokenProvider {
    private String authorizationHeader(HttpServletRequest request) {
        return request.getHeader(AUTHORIZATION);
    }
}
````

El segundo, verifica si el token recuperado de la cabecera tiene el formato bearer token:

````java

@Component
public class JwtTokenProvider {
    public boolean isBearerToken(HttpServletRequest request) {
        String bearerToken = this.authorizationHeader(request);
        return bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX) && bearerToken.split("\\.").length == 3;
    }
}
````

Y el tercero, retorna solo la cadena del token, sin ningún prefijo adicional:

````java

@Component
public class JwtTokenProvider {
    public String tokenFromRequest(HttpServletRequest request) {
        String bearerToken = this.authorizationHeader(request);
        return bearerToken.substring(TOKEN_PREFIX.length());
    }
}
````

Finalmente, la clase completa de **JwtTokenProvider** quedaría de esta manera:

````java

@Component
public class JwtTokenProvider {
    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final long EXPIRATION_TIME = 30 * 60 * 1000; //30min
    private static final String AUTHORITIES = "authorities";
    private static final String ISSUER = "System";
    private static final String AUTHORIZATION = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";
    @Value("${jwt.secret.key}")
    private String jwtSecretKey;

    public String createAccessToken(UserDetails userDetails) {
        return JWT.create()
                .withIssuer(ISSUER)
                .withAudience("User", "Managament", "Portal")
                .withIssuedAt(new Date())
                .withSubject(userDetails.getUsername())
                .withClaim(AUTHORITIES, this.authoritiesToCreateAccessToken(userDetails))
                .withExpiresAt(Instant.now().plusMillis(EXPIRATION_TIME))
                .sign(this.getAlgorithm());
    }

    public boolean isAccessTokenValid(String token) {
        try {
            this.jwtVerifier().verify(token);
            return true;
        } catch (AlgorithmMismatchException e) {
            LOG.error("El algoritmo del encabezado del token no es igual al del JWTVerifier: {}", e.getMessage());
        } catch (SignatureVerificationException e) {
            LOG.error("La firma no es válida: {}", e.getMessage());
        } catch (TokenExpiredException e) {
            LOG.error("El token ha expirado: {}", e.getMessage());
        } catch (MissingClaimException e) {
            LOG.error("Claim faltante: {}", e.getMessage());
        } catch (IncorrectClaimException e) {
            LOG.error("Claim incorrecto: {}", e.getMessage());
        } catch (JWTVerificationException e) {
            LOG.error("Excepción general de verificación de un JWT: {}", e.getMessage());
        }
        return false;
    }

    public String getSubjectFromAccessToken(String token) {
        return this.decodedJWT(token).getSubject();
    }

    public List<GrantedAuthority> getAuthoritiesFromAccessToken(String token) {
        return this.decodedJWT(token).getClaim(AUTHORITIES).asList(String.class).stream()
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    public boolean isBearerToken(HttpServletRequest request) {
        String bearerToken = this.authorizationHeader(request);
        return bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX) && bearerToken.split("\\.").length == 3;
    }

    public String tokenFromRequest(HttpServletRequest request) {
        String bearerToken = this.authorizationHeader(request);
        return bearerToken.substring(TOKEN_PREFIX.length());
    }

    private String authorizationHeader(HttpServletRequest request) {
        return request.getHeader(AUTHORIZATION);
    }

    private JWTVerifier jwtVerifier() {
        return JWT.require(this.getAlgorithm()).build();
    }

    private DecodedJWT decodedJWT(String token) {
        return this.jwtVerifier().verify(token);
    }

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC512(this.jwtSecretKey.getBytes());
    }

    private List<String> authoritiesToCreateAccessToken(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}

````

---

## Anulando la configuración de autorización del endpoint

Revisando la documentación oficial, existe un ejemplo donde nos muestran explícitamente la configuración de Spring
Security con los valores predeterminados, es decir, apenas agregamos la dependencia de Spring Security al proyecto, se
aplica una configuración predeterminada, dicha configuración es tal cual se muestra a continuación
([Ver el ejemplo en el repositorio oficial](https://github.com/spring-projects/spring-security-samples/blob/main/servlet/spring-boot/java/hello-security-explicit/src/main/java/example/SecurityConfiguration.java)):

````java

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
		http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().authenticated()
				)
				.httpBasic(withDefaults())
				.formLogin(withDefaults());
		// @formatter:on
        return http.build();
    }

    // @formatter:off
	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
	// @formatter:on

}
````

Como observamos en el código anterior, se muestra la habilitación del tipo de autenticación HTTP Basic Auth y el
Form Login Authentication, además de que para poder acceder a cualquier endpoint el usuario tiene que autenticarse.
Finalmente, observamos que el usuario por defecto es **user** y la contraseña se genera de manera aleatoria, que es la
contraseña que se muestra por defecto en consola.

Es importante haber mostrado la configuración por defecto que establece Spring Security, ya que **ahora tendremos
que anularlo para poder crear nuestra propia configuración.** Además, tal como se vio en el libro de **Spring Security
In Action 2020 [Pág. 48]** también creamos nuestra propia configuración de Spring Security, aunque en el libro se hace
uso de una versión antigua de Spring Security ,se usa la clase abstracta **WebSecurityConfigurerAdapter** que para
nuestro caso ya está deprecado, pero la idea es la misma, crear una clase de configuración para sobreescribir los
valores predeterminados de spring security.

Nuestra configuración que anula la configuración por defecto, será por el momento, el siguiente:

````java

@EnableWebSecurity(debug = true)
@Configuration
public class ApplicationSecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers("/api/v1/auth/**").permitAll();
                    authorize.anyRequest().authenticated();
                })
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
````

**DONDE**

- **@EnableWebSecurity(debug = true)**, agregue esta anotación a una clase @Configuration para tener la configuración de
  Spring Security definida en cualquier WebSecurityConfigurer o, más probablemente, exponiendo un bean
  SecurityFilterChain. **¿Necesito agregarlo a la clase de configuración?** Si no está utilizando spring-boot, sino solo
  un proyecto de spring puro, definitivamente necesita agregar @EnableWebSecurity para habilitar spring-security. Pero
  si está utilizando spring-boot 2.0 +, no necesita agregarlo usted mismo porque **la configuración automática de
  spring-boot lo hará automáticamente si olvida hacerlo.** En mi caso, lo dejaré agregado, de todos modos requiero
  mientras voy desarrollando que esté habilitado el ``debug=true``. Con el **debug=true** se puede **observar en consola
  todos los filtros involucrados en la solicitud actual**. Por ejemplo, haciendo una petición a nuestro endpoint de
  **/api/v1/auth/login** y con la configuración que viene por defecto en Spring Security, vemos en consola la lista de
  los filtros involucrados:

  ````
  Security filter chain: [
    DisableEncodeUrlFilter
    WebAsyncManagerIntegrationFilter
    SecurityContextHolderFilter
    HeaderWriterFilter
    CsrfFilter
    LogoutFilter
    UsernamePasswordAuthenticationFilter
    DefaultLoginPageGeneratingFilter
    DefaultLogoutPageGeneratingFilter
    BasicAuthenticationFilter
    RequestCacheAwareFilter
    SecurityContextHolderAwareRequestFilter
    AnonymousAuthenticationFilter
    ExceptionTranslationFilter
    AuthorizationFilter
  ]
  ````

  Ahora, hacemos la misma petición usando nuestra propia configuración:
  ````
  Security filter chain: [
    DisableEncodeUrlFilter
    WebAsyncManagerIntegrationFilter
    SecurityContextHolderFilter
    HeaderWriterFilter
    LogoutFilter
    BasicAuthenticationFilter
    RequestCacheAwareFilter
    SecurityContextHolderAwareRequestFilter
    AnonymousAuthenticationFilter
    ExceptionTranslationFilter
    AuthorizationFilter
  ]
  ````
  Vemos claramente que con nuestra configuración ya no aparecen los filtros:
  ``CsrfFilter, UsernamePasswordAuthenticationFilter, DefaultLoginPageGeneratingFilter,
  DefaultLogoutPageGeneratingFilter`` y de entre los que quedan hay dos muy interesantes: ``BasicAuthenticationFilter
  y el AuthorizationFilter``. Esta lista puede diferir según la configuración de seguridad y la ruta de acceso de la
  solicitud actual. Tenga en cuenta que el orden de los filtros importa, ya que se llaman en la secuencia en que se
  registran con el contenedor de servlets.


- **csrf(AbstractHttpConfigurer::disable)**, deshabilitamos el csrf, ya que nuestra aplicación no es una aplicación que
  renderiza el frontend (thymeleaf, jsp) y con el que se trabaja en formularios, sino, es una aplicación REST, por lo
  tanto al deshabilitar, nos va a permitir hacer peticiones POST, PUT, DELETE, caso contrario no nos permitirá.


- **authorize.requestMatchers("/api/v1/auth/\**").permitAll()**, permitimos todas las llamadas al endpoint .../auth,
  eso incluirá el login, y más adelante el register, etc. sin la necesidad de enviar credenciales.


- **authorize.anyRequest().authenticated()**, cualquier otra llamada que no se haya especificado previamente tendrá que
  autenticarse primero.


- **httpBasic(Customizer.withDefaults())**, dejamos habilitado el **BasicAuthenticationFilter**, mientras que el Form
  Login Authentication (UsernamePasswordAuthenticationFilter) que venía por defecto ya no está habilitado, eso significa
  que si ahora ingresamos por el navegador veremos que ya no nos muestra un login, sino más bien un popup de javascript
  para ingresar el username y password.

## Creando los DTO para enviar y recibir datos entre el cliente y servidor

````java
public record LoginRequestDTO(String username, String password) {
}
````

````java
public record LoginResponseDTO(String username, String accessToken, String refreshToken) {
}
````

## Creando controlador AuthController

Este controlador será el que permita hacer el **login**, **register** y **refreshToken** de los usuarios.

````java

@RestController
@RequestMapping(path = "/api/v1/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(path = "/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequestDTO) {
        return ResponseEntity.ok(this.authService.login(loginRequestDTO));
    }
}
````

## Creando el servicio AuthService

Nuestra clase de servicio implementará la lógica para hacer el **login, register y refreshToken**.

````java

@Service
public class AuthService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) {
        LOG.info("Logueando al usuario: {}", loginRequestDTO);

        // TODO authenticar al usuario

        return new LoginResponseDTO("test", "12345", "abcd");
    }

}
````

## Testeando desde "Anulando la configuración de autorización del endpoint"

Probamos el endpoint **/login** del controlador **AuthController** con datos que no están en la BD, solo estamos
probando para ver cómo recibe los datos y como nos devuelve desde el servicio.

````bash
curl -i -X POST -H "Content-Type: application/json" -d "{\"username\": \"martincillo\", \"password\": \"45725876\"}" http://localhost:8080/api/v1/auth/login
HTTP/1.1 200
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 30 Jun 2023 03:37:22 GMT

{"username":"test","accessToken":"12345","refreshToken":"abcd"}
````

---

## Configuraciones finales para iniciar sesión con usuarios

Si revisamos la imagen donde mostramos los componentes que interactúan en el flujo de autenticación en Spring Security,
veremos que el segundo componente es el **AuthenticationManager**, este componente tiene la responsabilidad del proceso
de autenticación. Para realizar este proceso, el AuthenticationManager delega a uno de los proveedores de autenticación
disponibles realizar la lógica de autenticación. El **AuthenticationProvider** usa el **UserDetailsService** y el
**PasswordEncoder** que definimos ya en capítulos anteriores, para efectuar la lógica de autenticación. Por esa razón,
es importante definir un **bean** del **AuthenticationManager** pues, será utilizado para inyectarlo, por ejemplo en la
clase de servicio **AuthService** y desde allí empezar a tener la responsabilidad del proceso de autenticación.

````java

@Configuration
public class SecurityConfig {
    /* omitted password encoder */

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
````

Ahora, usaremos el bean expuesto del **AuthenticationManager** en la clase **AuthService** donde implementaremos el
login con los datos que el usuario envía en el **LoginRequestDTO**.

````java

@Service
public class AuthService {
    /* omitted code */
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    /* omitted constructor */

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) {
        Authentication authentication = this.authenticate(loginRequestDTO.username(), loginRequestDTO.password());

        // Si hasta este punto llega y no lanzó ningún error, significa que sí se autenticó correctamente
        return this.loginResponse(authentication.getName());
    }

    private Authentication authenticate(String username, String password) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return this.authenticationManager.authenticate(authenticationToken);
    }

    @Transactional(readOnly = true)
    private LoginResponseDTO loginResponse(String username) {
        Optional<User> userOptional = this.userRepository.findUserByUsername(username);
        UserDetails userDetails = new SecurityUser(userOptional.orElseThrow());
        String accessToken = this.jwtTokenProvider.createAccessToken(userDetails);
        LOG.info("Usuario logueado: {}", username);
        LOG.info("AccessToken: {}", accessToken);
        return new LoginResponseDTO(username, accessToken, "--no-disponible-aún--");
    }
}
````

Primero explicaré los métodos privados, los separé para que sea más ordenado.

El método privado **authenticate(...)** tiene como parámetros un usuario y una contraseña que serán usados para crear un
nuevo objeto del tipo **UsernamePasswordAuthenticationToken(...)** que es una implementación de la interfaz
**Authentication**, de esta implementación usamos el **constructor de dos parámetros**, ya que **existe también un
constructor de 3 parámetros**, pero, **¿cuál es la diferencia?**, usamos el constructor con
dos parámetros cuando construimos inicialmente el objeto de autenticación **y aún no está autenticado**, es decir, si
ingresamos al constructor de 2 parámetros veremos que tenemos un **setAuthenticated(false)** indicándonos lo ya
mencionado.

**NOTA**
> Recordar que el **AuthenticationProvider** es el que implementa la lógica de autenticación haciendo uso del
> UserDetailsService y PasswordEncoder. Ahora, cuando el **AuthenticationProvider** autentica la solicitud, crea una
> instancia de autenticación utilizando, ¡ahora sí!, el constructor con 3 parámetros
> del UsernamePasswordAuthenticationToken, lo que crea un objeto autenticado. Este detalle es importante porque el
> método authenticate() del **AuthenticationProvider** tiene que devolver una instancia autenticada. Si revisamos el
> constructor con 3 parámetros veremos que tenemos un **super.setAuthenticated(true);** indicándonos
> lo mencionado.
>
> El **UsernamePasswordAuthenticationToken** es una implementación de la interfaz **Authentication** y representa una
> solicitud de autenticación estándar con username y password.

Ahora, dentro el método **authenticate(...)** se hace uso del **AuthenticationManager**, el cual inyectamos vía
constructor de la clase. Este **authenticationManager** hace uso de su método **authenticate(...)** al que le pasamos
la implementación **UsernamePasswordAuthenticationToken**. Este método intenta autenticar al objeto de autenticación
pasada, devolviendo un objeto **Authentication** completo (incluidos los authorities) si la autenticación tiene éxito.

**NOTA**

> Un AuthenticationManager debe cumplir el siguiente contrato con respecto a las excepciones:
>
> - Se debe lanzar un **DisabledException** si una cuenta está deshabilitada y el AuthenticationManager puede probar
    este estado.
> - Se debe lanzar un **LockedException** si una cuenta está bloqueada y AuthenticationManager puede probar el bloqueo
    de la cuenta.
> - Se debe lanzar un **BadCredentialsException** si se presentan credenciales incorrectas. Si bien las excepciones
    anteriores son opcionales, un AuthenticationManager siempre debe probar las credenciales.


En pocas palabras, si la autenticación falla lanzará la excepción **AuthenticationException**, por lo tanto, el proceso
de autenticación finaliza con la excepción.

El método privado **loginResponse(username)**, recupera información de un User en función de su username, crea un
UserDetails y a partir de él genera un **accessToken** para posteriormente devolverlos al cliente.

Ahora sí, nuestro método público **login()**. Este método recibe el username y password del usuario, luego usa el
método privado **authenticate()** para autenticar dichas credenciales. ``Si hasta ese punto el método privado
authenticate() no lanza ninguna excepción, significa que se autenticó correctamente``. Finalmente, como respuesta el
método **login()** responde con el objeto LoginResponseDTO poblado (con el username, accessToken, refreshToken).

### Clases que interactúan en el proceso de autenticación del login

Recordar que en nuestro **AuthService** inyectamos el **AuthenticationManager** para realizar el proceso de
autenticación con las credenciales enviadas por el cliente. Lo primero que sucede es que una implementación del
**AuthenticationManager**, en este caso el **ProviderManager** es el que recibe el objeto
**UsernamePasswordAuthenticationToken** en su método **authenticate(..)**. Recordemos que el **AuthenticationManager**
delega al **AuthenticationProvider** realizar la lógica de autenticación, en este caso, la implementación del
**AuthenticationManager**, o sea el **ProviderManager** delega realizar esa lógica de autenticación a una implementación
del authenticationProvider, en este caso será el **DaoAuthenticationProvider**.

**NOTA**

> La configuración predeterminada en Spring Boot establece el **DaoAuthenticationProvider como el proveedor de
> autenticación principal.** Sin embargo, es posible personalizar esta configuración y utilizar diferentes
> implementaciones del AuthenticationProvider según tus necesidades específicas.

Para finalizar, un último comentario de lo visto hasta ahora, pero antes, recordemos el flujo de los componentes
principales que interactúan en el proceso de autenticación de Spring Security:

![Main-components-authentication-spring-security](./assets/01.Main-components-authentication-spring-security.png)

Como vemos la imagen anterior, el proceso de autenticación arranca desde el **AuthenticationFilter**, pero en nuestro
proceso de hacer login, en este caso en particular, nos fuimos directamente al **AuthenticationManager**. Recordemos que
creamos el endpoint ``/api/v1/auth/login`` para que sea accedido con total libertad por cualquier usuario. Por lo tanto,
cuando ingresamos a ese endpoint, ya estamos dentro de la aplicación, y a partir de aquí lo que queremos hacer es
seguir el mismo flujo que seguiría un **AuthenticationFilter** que es llamar al **AuthenticationManager**, luego este al
**AuthenticationProvider**, etc... con la finalidad de autenticar al usuario con el username y password enviado a
ese endpoint y si el **authenticationManager.authenticate(...)** no lanza ninguna excepción retornamos al cliente
un **accessToken** que usará en los request a otros recursos.

**¿Y en nuestro caso, cuándo arrancaremos el proceso de autenticación desde el AuthenticationFilter?** Pues, luego de
haber realizado el login con éxito y haber obtenido un **accessToken**, usaremos ese **accessToken** para enviarlo en
cada petición cuando quisiéramos acceder a algún recurso protegido, es en ese instante, que se utilizará una
implementación del **AuthenticationFilter** (le llamaremos **JwtAuthenticationFilter**) quien interceptará los
**requests**, obtendrá el **accessToken** y hará todo el proceso de autenticación que vemos en la imagen anterior.

## Probando la funcionalidad de iniciar sesión

**[200 OK]** Hacemos un **login exitoso** con el usuario martin, vemos que **nos retorna el accessToken** correctamente:

````bash
curl -i -X POST -H "Content-Type: application/json" -d "{\"username\": \"martin\", \"password\": \"12345\"}" http://localhost:8080/api/v1/auth/login
HTTP/1.1 200
Content-Type: application/json
...

{ 
  "username":"martin",
  "accessToken":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "refreshToken":"--no-disponible-aún--"
}
````

**[401Unauthorized]** Hacemos login con un **usuario correcto** pero una **contraseña incorrecta:**

````bash
curl -i -X POST -H "Content-Type: application/json" -d "{\"username\": \"martin\", \"password\": \"000000\"}" http://localhost:8080/api/v1/auth/login
HTTP/1.1 401
Set-Cookie: JSESSIONID=BB4C3A1A925067A47102E6DD280E9F2F
WWW-Authenticate: Basic realm="Realm"
...
````

**[401Unauthorized]** Hacemos login con un **usuario incorrecto:**

````bash
curl -i -X POST -H "Content-Type: application/json" -d "{\"username\": \"hacker\", \"password\": \"000000\"}" http://localhost:8080/api/v1/auth/login
HTTP/1.1 401
Set-Cookie: JSESSIONID=A9F44246F9E1E6EEF9EA58DF56818632; Path=/; HttpOnly
WWW-Authenticate: Basic realm="Realm"
...
````

**[401Unauthorized]** Hacemos login **sin enviarle credenciales:**

````bash
curl -i -X POST http://localhost:8080/api/v1/auth/login
HTTP/1.1 401
Set-Cookie: JSESSIONID=29E6B2ECB66C44FD1F29DECF2997721E; Path=/; HttpOnly
WWW-Authenticate: Basic realm="Realm"
...
````

---

## Creando filtro de autenticación para verificación del access token

Crearemos un filtro personalizado llamado **JwtAuthenticationFilter** para procesar el access token que envía el
cliente. Si recordamos los componentes que intervienen en el flujo de autenticación en Spring Security inician con el
**AuthenticationFilter**, luego pasa al **AuthenticationManager** y así sucesivamente hasta terminar de registrar al
usuario en el **Security Context** siempre y cuando la autenticación haya sido exitosa.

En nuestro caso, utilizaremos este filtro personalizado **JwtAuthenticationFilter** para realizar, casi de la misma
forma, el proceso de autenticación, y digo **casi de la misma forma**, ya que aquí estaremos trabajando con un
**accessToken**, eso significa que solo necesitamos verificar la validez del token y obtener el usuario y sus
authorities del mismo token, así ya no necesitamos ir a la base de datos a recuperar detalles del usuario, porque todo
lo haremos con el token recibido.

Una vez que hayamos validado el token y hayamos obtenido el usuario y sus authorities, crearemos un objeto de
autenticación del tipo **UsernamePasswordAuthenticationToken** pero el del **constructor de 3 parámetros**. Si volvemos
al flujo de autenticación que define Spring Security, su componente **AuthenticationProvider** cuando va a autenticar
una solicitud, crea una instancia de autenticación utilizando el constructor con 3 parámetros del
**UsernamePasswordAuthenticationToken**, lo que crea un objeto autenticado. Ahora, volviendo a nuestro caso particular,
luego de haber validado el token y obtenido el username y authorities, necesitamos crear la misma instancia de
autenticación con los 3 parámetros, ahora si revisamos dicho constructor veremos que tiene un
**super.setAuthenticated(true)**.

Luego de tener nuestra instancia autenticada, debemos registrarlo en el **Security Context**, tal cual lo hace el
AuthenticationFilter una vez que ha verificado con éxito todo el proceso de autenticación.

**¿Por qué debemos registrarlo en el Security Context?**, porque después de haber realizado dicho registro, al finalizar
los demás filtros, se delega la solicitud al **Authorization Filter** quien **usará los datos registrados en el Security
Context** para decidir **si autorizar el acceso** del usuario al recurso que ha solicitado **o denegar su acceso.**

````java

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger LOG = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!this.jwtTokenProvider.isBearerToken(request)) {
            LOG.error("No procesó la solicitud de autenticación porque no pudo encontrar el formato bearer token en " +
                    "el encabezado de autorización");
            filterChain.doFilter(request, response);
            return;
        }

        String token = this.jwtTokenProvider.tokenFromRequest(request);

        if (!this.jwtTokenProvider.isAccessTokenValid(token)) {
            LOG.error("El access token proporcionado no pasó la validación de la librería auth0/java-jwt");
            filterChain.doFilter(request, response);
            return;
        }

        // Hasta este punto se verificó la validez del access token, por lo tanto, inicia el proceso de autenticación
        // y registro de los datos en el Security Context

        // Recuperamos el usuario y los authorities desde el mismo token
        String username = this.jwtTokenProvider.getSubjectFromAccessToken(token);
        List<GrantedAuthority> authorities = this.jwtTokenProvider.getAuthoritiesFromAccessToken(token);

        // Creamos una instancia autenticada con el constructor de 3 parámetros. El segundo parámetro que es la contraseña
        // ya no va, porque ya verificamos que es un usuario válido y para eso usamos la verificación del accessToken
        var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);

        // Establecemos detalles adicionales de la autenticación con los datos del request: como dirección ip 
        // del cliente, detalles del agente de usuario, etc. y hacerla accesible durante la ejecución de la 
        // lógica de seguridad de Spring
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        // Actualizamos el contexto de seguridad
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Dejamos que pase la llamada al siguiente filtro en la cadena de filtros
        filterChain.doFilter(request, response);
    }
}
````

## Creando una implementación del AuthenticationEntryPoint

El método de nuestra implementación se ejecutará cada vez que ocurra un **AuthenticationException**, es decir, cuando un
cliente está intentando acceder a un recurso protegido, la aplicación con esta excepción le indicará que **primero
necesita autenticarse** lanzándole un **401 Unauthorized** y un conjunto de datos adicionales en el body, como el
**status, error, mensaje, path.**

**También podría lanzarse este método si ocurre un error en la autenticación** y no solamente por acceder a un recurso
protegido sin antes estar autenticado.

````java

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private static final Logger LOG = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        LOG.error("La solicitud requiere autenticación");

        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());
        body.put("message", authException.getMessage());
        body.put("path", request.getServletPath());
        body.put("ejemplo", "Caracteres con Perú Ñandú");

        final ObjectMapper mapper = new ObjectMapper();

        // Configuramos la respuesta a retornar
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        mapper.writeValue(response.getOutputStream(), body);
    }
}
````

**Donde**

- **ObjectMapper**, nos permite convertir cualquier objeto en un JSON. proporciona funcionalidad para leer y escribir
  JSON, ya sea hacia y desde POJO básicos (Plain Old Java Objects) o hacia y desde un modelo de árbol JSON de propósito
  general (JsonNode), así como la funcionalidad relacionada para realizar conversiones.
- **mapper.writeValue(response.getOutputStream(), body)**, usamos el método **writeValue(..)** para convertir el objeto
  HashMap en un JSON. Este método se puede usar para serializar cualquier valor de Java como salida JSON, usando el
  flujo de salida proporcionado, en nuestro caso usamos el response.getOutputStream() **(usando la codificación
  JsonEncoding.UTF8).**

## Creando una implementación del AccessDeniedHandler

El método de nuestra implementación se ejecutará cada vez que ocurra un **AccessDeniedException**, es decir cuando un
**usuario se autentica correctamente, pero está intentando acceder a un recurso para el que no tiene el permiso
adecuado** y como respuesta le enviamos un **403 Forbidden** además de un conjunto de datos adicionales como el
status, error, etc.

````java

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    private static final Logger LOG = LoggerFactory.getLogger(JwtAccessDeniedHandler.class);

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        LOG.error("La autenticación fue exitosa, pero no tiene privilegios para acceder al recurso solicitado");

        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_FORBIDDEN);
        body.put("error", HttpStatus.FORBIDDEN.getReasonPhrase());
        body.put("message", accessDeniedException.getMessage());
        body.put("path", request.getServletPath());

        final ObjectMapper mapper = new ObjectMapper();

        // Configuramos la respuesta a retornar
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        mapper.writeValue(response.getOutputStream(), body);
    }
}
````

## Agregando el JwtAuthenticationFilter, JwtAuthenticationEntryPoint y el JwtAccessDeniedHandler a la configuración

Realizamos la inyección de dependencia de los 3 componentes desarrollados en esta sección dentro de nuestra clase de
configuración principal de Spring Security.

Quizá la configuración más importante que vale la pena comentar es el de nuestro filtro personalizado. Debemos agregar
nuestro filtro **JwtAuthenticationFilter** antes del filtro **UsernamePasswordAuthenticationFilter** para que sea
agregado en la cadena de filtros, precisamente antes de ese filtro.

Recordemos que el **UsernamePasswordAuthenticationFilter** utiliza un tipo de autenticación basada en username y
password, mientras que en nuestro filtro usamos un tipo de autenticación basado en tokens, donde los tokens JWT se
utilizan para la autenticación en lugar de las credenciales tradicionales como usuario y contraseña. De todas maneras,
en nuestra configuración no tenemos habilitado el filtro **UsernamePasswordAuthenticationFilter**, pero le estamos
indicando a Spring Security que nuestro filtro personalizado lo ubique en una posición anterior a la ubicación donde
estaría el filtro **UsernamePasswordAuthenticationFilter**.

Para comprobar lo mencionado en el apartado anterior, habilité temporalmente el
**formLogin(Customizer.withDefaults())**, luego ejecuté la aplicación e hice una petición a la lista de productos usando
``curl -i http://localhost:8080/api/v1/products``, obviamente no voy a recibir la lista de productos porque necesito
autenticarme, simplemente hice la petición para que en consola se muestre la lista de cadenas de filtro de seguridad,
eso gracias a que tengo habilitado el ``@EnableWebSecurity(debug = true)``. Ahora, revisando el **Security filter
chain** que se muestra en consola vemos que nuestro filtro **JwtAuthenticationFilter se encuentra ubicado antes del
UsernamePasswordAuthenticationFilter**.

````
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  LogoutFilter
  JwtAuthenticationFilter                 <-----------
  UsernamePasswordAuthenticationFilter    <-----------
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
````

Ahora, quitamos la configuración del **formLogin(Customizer.withDefaults())** porque no lo requerimos en nuestra
aplicación, volvemos a ejecutar y hacemos nuevamente una petición. Si revisamos la consola, veremos que el filtro
**UsernamePasswordAuthenticationFilter** ya no está habilitado, mientras que nuestro filtro **JwtAuthenticationFilter**
aún sigue manteniendo su posición dentro de la cadena de filtros.

````
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  LogoutFilter
  JwtAuthenticationFilter                 <-----------
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
````

Otro cambio que hice fue quitarle la configuración que agrega el filtro para la autenticación HTTP Basic, me refiero
al siguiente código: **httpBasic(Customizer.withDefaults())**, de esta manera, dejamos solo nuestro filtro de
autenticación de JWT, eso significa que para poder acceder a cualquier recurso protegido ya no enviaremos en cada
solicitud un user y un password en la cabecera, sino más bien, usaremos el jwt generado al hacer login previamente.

Finalmente, hasta este punto, nuestra clase de configuración quedaría de la siguiente manera:

````java

@EnableWebSecurity(debug = true)
@Configuration
public class ApplicationSecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public ApplicationSecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                                     JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                                     JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers("/api/v1/auth/**").permitAll();
                    authorize.anyRequest().authenticated();
                })
                .exceptionHandling(exceptionHandling -> {
                    exceptionHandling.authenticationEntryPoint(this.jwtAuthenticationEntryPoint);
                    exceptionHandling.accessDeniedHandler(this.jwtAccessDeniedHandler);
                })
                .addFilterBefore(this.jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
````

---

## Configurando CORS

Para tener un mejor panorama de este tema, en el libro de **Spring Security In Action 2020**
[**Capítulo 10 applying csrf protection and
cors**](https://github.com/magadiflo/spring-security-in-action-2020/blob/main/10.applying_csrf_protection_and_cors.md)
se habla con mayor detalle.

El uso **compartido de recursos de origen cruzado (cross-origin resource sharing - CORS)** se refiere a la situación en
la que una aplicación web alojada en un dominio específico intenta acceder al contenido de otro dominio. **De forma
predeterminada, el navegador no permite que esto suceda**. La configuración CORS le permite que una parte de sus
recursos se llame desde un dominio diferente en una aplicación web que se ejecuta en el navegador.

Por ejemplo, supongamos que nuestro backend está ejecutándose en el dominio **api-jwt.com**, mientras que tenemos
desarrollado una aplicación cliente que se está ejecutando en el dominio **angular-client.com**, entonces, con la
habilitación de cors le estamos diciendo a nuestro backend que permita la llamada del dominio **angular-client.com**,
solo llamadas de ese dominio, las demás serán rechazadas.

Como primer ejemplo, veamos qué pasa si intentamos llamar desde una aplicación de Angular que está en el puerto 4200,
a nuestra aplicación de Spring Boot que está en el puerto 8080, de por sí, esto se consideraría como
**dominios distintos**:

````
Access to XMLHttpRequest at 'http://localhost:8080/api/v1/products' from origin 'http://localhost:4200' 
has been blocked by CORS policy: 
Response to preflight request doesn't pass access control check: 
No 'Access-Control-Allow-Origin' header is present on the requested resource.

GET http://localhost:8080/api/v1/products net::ERR_FAILED
````

Cuando la aplicación cliente realiza la solicitud, espera que la respuesta tenga un encabezado
**Access-Control-Allow-Origin** que contenga los orígenes aceptados por el servidor. Si esto no sucede, como en el caso
del comportamiento predeterminado de Spring Security, **el navegador no aceptará la respuesta.**

Ahora, qué pasa si agregamos la siguiente configuración para **CORS** en nuestra aplicación backend.

1. Habilitamos **CORS** en el archivo principal de configuración de Spring Security.
2. Creamos un **@Bean** exponiendo las configuraciones del cors. Si optamos por esta forma, como mínimo debe
   configurarse los **orígenes permitidos y los métodos permitidos**.

````java

@EnableWebSecurity(debug = true)
@Configuration
public class ApplicationSecurityConfig {
    /* omitted code */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults());
        /* omitted code */
        return http.build();
    }
}
````

Como segundo paso, exponemos un bean con las configuraciones del cors. En este caso estamos proporcionando un bean que
expone un **CorsFilter**. En otras configuraciones que he revisado, el bean que se expone es una implementación del
**CorsConfigurationSource** es decir el **UrlBasedCorsConfigurationSource** que usa el objeto **CorsConfiguration**.
En nuestro caso usamos el objeto del **UrlBasedCorsConfigurationSource**, para crear un nuevo **CorsFilter pasándole
el objeto por el constructor**. Cualquiera de las dos formas es válida según el comentario del código fuente:

> **Agrega un CorsFilter** para ser utilizado. **Si se proporciona un bean con el nombre de corsFilter**, se **utiliza
> ese CorsFilter.** De lo contrario, si se define corsConfigurationSource, entonces se usa CorsConfiguration.
> De lo contrario, si Spring MVC está en el classpath, se usa un HandlerMappingIntrospector.

````java

@Configuration
public class SecurityConfig {
    /* omitted code */

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Origin", "Content-Type", "Accept", "Authorization",
                "Access-Control-Allow-Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers",
                "X-Requested-With"));
        configuration.setExposedHeaders(Arrays.asList("Origin", "Content-Type", "Accept", "Authorization",
                "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // "/**", representa todas las rutas del backend

        return new CorsFilter(source);
    }
}
````

**NOTA**

> Existen otras formas de configurar CORS en nuestra aplicación de Spring Boot, podemos agregar la anotación
> **@CrossOrigin("http://localhost:4200")** directamente sobre el método que define el endpoint y configurarlo
> utilizando los orígenes y métodos permitidos. Esta anotación **@CrossOrigin("http://localhost:4200")** también puede
> ser colocado a nivel del controlador para que aplique a todos los endpoints del mismo.


Para finalizar el tema de cors, cuando habilitamos la configuración de cors, automáticamente se agrega un nuevo filtro
**CorsFilter** a la cadena de filtros de seguridad de Spring Security.

````
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CorsFilter                  <--------------
  LogoutFilter
  JwtAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
````

Volvemos a realizar la solicitud dede nuestra aplicación de Angular (http://localhost:4200/home) hacia nuestra
aplicación de Spring Boot (http://localhost:8080/api/v1/products)

````
(4) [{…}, {…}, {…}, {…}]
0: {id: 1, name: 'Pc gamer', price: 3500}
1: {id: 2, name: 'Teclado inalámbrico', price: 150.8}
2: {id: 3, name: 'Mouse inalámbrico', price: 99.9}
3: {id: 4, name: 'Celular Samsung A7', price: 5900}
length: 4
````

Como vemos, ahora ya nos muestra la respuesta correcta, eso significa que nuestra configuración de **CORS** habilitado
y configurado en nuestro backend está funcionando, obviamente en la petición hemos tenido que mandarle un accessToken,
ya que hasta este punto tenemos securizados los endpoints.

## Configurando el SessionCreationPolicy STATELESS

**Por defecto la aplicación en Spring Security trabaja con sesiones de usuario**, para comprobarlo haremos una llamada
al endpoint de productos y veremos la cabecera de respuesta, una **cookie de sesión** o **cookie de identificación
de sesión**. Esta cookie contiene un identificador único, como un ID de sesión, que se utiliza para asociar al cliente
con una sesión específica en el servidor. La información real de la sesión se almacena en el servidor, no en la cookie
en sí.

````bash
curl -i http://localhost:8080/api/v1/products
HTTP/1.1 401
...
Set-Cookie: JSESSIONID=BC19E3876EC71DC70929286EBFBBEDD4; Path=/; HttpOnly <------------------------
...

{
  "path":"/api/v1/products",
  "error":"Unauthorized",
  "message":"Full authentication is required to access this resource",
  "status":401,
  "ejemplo":"Caracteres con Perú Ñandú"
}
````

Recordar que el concepto de sessions es individual de cada usuario que se conecta a nuestra aplicación y la información
no es compartida entre ellos. Así pues, cada usuario dispondrá de su propio HashMap en donde almacenar la información
que resulte útil entre páginas. Es accedida exclusivamente del lado del servidor.

Ahora, si habilitamos la configuración para que nuestra aplicación sea del tipo **STATELESS** (sin estado), veremos que
**Spring Security nunca creará un HttpSession y nunca la usará para obtener el SecurityContext.** Esto es útil en
arquitecturas basadas en servicios web RESTful, donde cada solicitud debe contener toda la información necesaria para
procesarla de manera independiente, sin depender del estado almacenado en el servidor:

````java

@EnableWebSecurity(debug = true)
@Configuration
public class ApplicationSecurityConfig {
    /* omitted code */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                /*omitted code*/
                .sessionManagement(sessionManagement -> {
                    sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                });

        /*omitted code*/
        return http.build();
    }
}
````

Luego si volvemos a ejecutar la petición veremos que ya no tenemos la **cookie de sesión**:

````bash
curl -i http://localhost:8080/api/v1/products
HTTP/1.1 401
...

{ 
  "path":"/api/v1/products",
  "error":"Unauthorized",
  "message":"Full authentication is required to access this resource",
  "status":401,
  "ejemplo":"Caracteres con Perú Ñandú"
}
````

Finalmente, podemos ver que, habiendo habilitado el **sessionManagement** en el archivo de configuración principal de
Spring Security, podemos ver que se agrega un nuevo filtro, el **SessionManagementFilter**

````
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CorsFilter
  LogoutFilter
  JwtAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  SessionManagementFilter       <--------------------
  ExceptionTranslationFilter
  AuthorizationFilter
]
````

## Asegurando los endpoints en base a los roles de usuario

Observemos la imagen inferior, para recordar cuál es el paso siguiente al proceso de autenticación. Vemos que luego
de que ha ocurrido una autenticación exitosa, los detalles del usuario autenticado son almacenados en el SecurityContext
y se reenvía la solicitud al **authentication filter**. El **authentication filter** decide si la llamada es permitida
o no, para eso usa el detalle almacenado en el **Security Context**.

![](./assets/02.Flow-authorization.png)

Si observamos todas los **Security filter chain** mostrados a lo largo de este archivo, veremos que en la parte inferior
se encuentra el filtro **AuthorizationFilter**, y se muestra como último filtro porque es, digamos, el filtro final
luego de que ya ha pasado el proceso de autenticación.

````
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CorsFilter
  LogoutFilter
  JwtAuthenticationFilter
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  SessionManagementFilter       
  ExceptionTranslationFilter
  AuthorizationFilter           <--------------------
]
````

Nuestro **JwtAuthenticationFilter** luego de verificar que el **accessToken** sea válido, almacena la información
el usuario en el **SecurityContext**:

````
SecurityContextHolder.getContext().setAuthentication(authentication);
````

Ahora, el **AuthorizationFilter** utilizará esa información para darle permiso al usuario de acceder a un endpoint
en específico, según el rol que tenga definido.

Podemos configurar el acceso a los endpoints en el mismo archivo de configuración de Spring Security, tal como lo
tenemos configurado para el endpoint de **/auth**:

````
.authorizeHttpRequests(authorize -> {
    authorize.requestMatchers("/api/v1/auth/**").permitAll();
    authorize.anyRequest().authenticated();
})
````

Pero en mi caso, lo haré de otra manera. Lo primero que haremos será agregar la anotación **@EnableMethodSecurity** en
la clase de configuración principal de Spring Security. Esta anotación nos permite habilitar el uso de otras
anotaciones, para nuestro caso el uso de la anotación **@PreAuthorize()** para establecer seguridad a nivel de método.

````java

@EnableMethodSecurity  //prePostEnabled = true (default)
@EnableWebSecurity(debug = true)
@Configuration
public class ApplicationSecurityConfig {
    /* omitted code */
}
````

**NOTA**

> En versiones anteriores de Spring Security, se usaba la anotación
> **@EnableGlobalMethodSecurity(prePostEnabled = true)**, allí sí había la necesidad de especificar que habilite
> la anotación **@PreAuthorize()** y **@PostAuthorize()**, ya que por defecto **prePostEnabled = false**.
>
> En nuestra versión de Spring Security **viene por defecto en true**, por eso tan solo necesitamos agregar la
> anotación @EnableMethodSecurity, y listo.

Ahora solo toca agregar la anotación **@PreAuthorize(...)** definiendo en su interior los roles que accederán a cada
endpoint. Como estamos trabajando con ROLES, usamos los métodos **hasRole(...)**, **hasAnyRole(...)**, solo definimos
el rol sin agregarle el prefijo **ROLE_**, serán los métodos **hasRole() y hasAnyRole()** quienes internamente lo hagan
por nosotros.

````java

@RestController
@RequestMapping(path = "/api/v1/products")
public class ProductController {

    /* omitted code */

    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'USER')")
    @GetMapping
    public ResponseEntity<List<Product>> getAllProducts() { /* omitted code */ }

    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN', 'USER')")
    @GetMapping(path = "/{id}")
    public ResponseEntity<Product> getProduct(@PathVariable Long id) { /* omitted code */ }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<Product> saveProduct(@RequestBody Product product) { /* omitted code */ }

    @PreAuthorize("hasAnyRole('ADMIN')")
    @PutMapping(path = "/{id}")
    public ResponseEntity<Product> updateProduct(@PathVariable Long id, @RequestBody Product product) { /* omitted code */ }

    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @DeleteMapping(path = "/{id}")
    public ResponseEntity<?> deleteProduct(@PathVariable Long id) { /* omitted code */ }
}
````

Accediendo con el usuario **nuria**, role **USER** al listado de productos. Lo mismo debería suceder con los usuarios
**martin y eli:**

````bash
curl -i -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJhdWQiOlsiVXNlciIsIk1hbmFnYW1lbnQiLCJQb3J0YWwiXSwiaWF0IjoxNjg4MzQ3MjEzLCJzdWIiOiJudXJpYSIsImF1dGhvcml0aWVzIjpbIlJPTEVfVVNFUiJdLCJleHAiOjE2ODgzNDkwMTN9.b-MEzEp4O0xqQsfI2nXx92KXZIjbvNeLzXrqwP9AhDCwPzoAxmqkQoBTmz8zQ8TKMjhxweQ4Dy1pwSyh67Jdxg" http://localhost:8080/api/v1/products
HTTP/1.1 200
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 03 Jul 2023 01:22:18 GMT

[
  {"id":1,"name":"Pc gamer","price":3500.0},
  {"id":2,"name":"Teclado inalámbrico","price":150.8},
  {"id":3,"name":"Mouse inalámbrico","price":99.9},
  {"id":4,"name":"Celular Samsung A7","price":5900.0}
]
````

Accediendo con el usuario **nuria**, role **USER** para guardar un producto, sabiendo que ese endpoint está restringido
solo para usuarios con rol **ADMIN**:

````bash
curl -i -X POST -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJhdWQiOlsiVXNlciIsIk1hbmFnYW1lbnQiLCJQb3J0YWwiXSwiaWF0IjoxNjg4MzQ3MjEzLCJzdWIiOiJudXJpYSIsImF1dGhvcml0aWVzIjpbIlJPTEVfVVNFUiJdLCJleHAiOjE2ODgzNDkwMTN9.b-MEzEp4O0xqQsfI2nXx92KXZIjbvNeLzXrqwP9AhDCwPzoAxmqkQoBTmz8zQ8TKMjhxweQ4Dy1pwSyh67Jdxg" -H "Content-Type: application/json" -d "{\"name\": \"Bicicleta\", \"price\": 850.50}" http://localhost:8080/api/v1/products
HTTP/1.1 403
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Content-Length: 86
Date: Mon, 03 Jul 2023 01:26:01 GMT

{
  "path":"/api/v1/products",
  "error":"Forbidden",
  "message":"Access Denied",
  "status":403
}
````

Ahora, accedemos al mismo endpoint para guardar un producto, pero con el accessToken correspondiente a un usuario cuyo
rol es **ADMIN**, en este caso con el usuario **eli**:

````bash
curl -i -X POST -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJhdWQiOlsiVXNlciIsIk1hbmFnYW1lbnQiLCJQb3J0YWwiXSwiaWF0IjoxNjg4MzQ3MjAxLCJzdWIiOiJlbGkiLCJhdXRob3JpdGllcyI6WyJST0xFX0FETUlOIl0sImV4cCI6MTY4ODM0OTAwMX0.BpuUbqSDwYFMTdnHJXexpA7i2COC311bIwmiIetn5p4L7s9BfHpxslf5MnWgepcHKi--mdaEixB2b9tyorKAVA" -H "Content-Type: application/json" -d "{\"name\": \"Bicicleta\", \"price\": 850.50}" http://localhost:8080/api/v1/products
HTTP/1.1 201
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Location: /api/v1/products/5
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 03 Jul 2023 01:28:38 GMT

{"id":5,"name":"Bicicleta","price":850.5}
````

Ahora, tratamos de eliminar un producto con el accessToken correspondiente a un **ADMIN**, veremos que no se podrá,
ya que dicho endpoint solo puede ser accedido por un usuario del tipo **SUPER_ADMIN**:

````bash
curl -i -X DELETE -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJhdWQiOlsiVXNlciIsIk1hbmFnYW1lbnQiLCJQb3J0YWwiXSwiaWF0IjoxNjg4MzQ3MjAxLCJzdWIiOiJlbGkiLCJhdXRob3JpdGllcyI6WyJST0xFX0FETUlOIl0sImV4cCI6MTY4ODM0OTAwMX0.BpuUbqSDwYFMTdnHJXexpA7i2COC311bIwmiIetn5p4L7s9BfHpxslf5MnWgepcHKi--mdaEixB2b9tyorKAVA" http://localhost:8080/api/v1/products/3
HTTP/1.1 403
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Content-Length: 88
Date: Mon, 03 Jul 2023 01:30:32 GMT

{"path":"/api/v1/products/3","error":"Forbidden","message":"Access Denied","status":403}
````

Finalmente, accedemos al endpoint anterior con el usuario **martin** cuyo rol es **SUPER_ADMIN**:

````bash
curl -i -X DELETE -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJhdWQiOlsiVXNlciIsIk1hbmFnYW1lbnQiLCJQb3J0YWwiXSwiaWF0IjoxNjg4MzQ3MTg1LCJzdWIiOiJtYXJ0aW4iLCJhdXRob3JpdGllcyI6WyJST0xFX1NVUEVSX0FETUlOIl0sImV4cCI6MTY4ODM0ODk4NX0.C5iChtuMdI74fiBqgcAHA0a811Rwd8AuVRMg_Vkv0Zlr4ByxebRQHxivjQWGCgJfre2tuiRwyq7_bRwVjTCLFQ" http://localhost:8080/api/v1/products/3
HTTP/1.1 204
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Date: Mon, 03 Jul 2023 01:33:27 GMT
````

---

## Obtener AccessToken y Refresh Token al hacer login

La clase **JwtTokenProvider** es la clase que sufrirá mayor modificación. En esta clase, definiremos el método que nos
retornará un **refreshToken** conteniendo detalles mínimos y un tiempo de expiración superior al tiempo definido en el
**accessToken**.

Como observamos en el código inferior, cambiamos el nombre de la variable **EXPIRATION_TIME** por
**EXPIRATION_ACCESS_TOKEN** para darle mayor sentido semántico a la variable. Además, colocamos el código que retorna
el **accessToken**, ya que en ese punto hacemos uso de la variable **EXPIRATION_ACCESS_TOKEN**, de la misma manera
la implementación que realizamos para el **refreshToken**.

````java

@Component
public class JwtTokenProvider {
    /* omitted code */
    private static final long EXPIRATION_ACCESS_TOKEN = 30 * 60 * 1000; //30min
    private static final long EXPIRATION_REFRESH_TOKEN = (2 * EXPIRATION_ACCESS_TOKEN) + (4 * 60 * 60 * 1000) + (60 * 1000); //5h 1m

    public String createAccessToken(UserDetails userDetails) {
        return JWT.create()
                .withIssuer(ISSUER)
                .withAudience("User", "Managament", "Portal")
                .withIssuedAt(new Date())
                .withSubject(userDetails.getUsername())
                .withClaim(AUTHORITIES, this.authoritiesToCreateAccessToken(userDetails))
                .withExpiresAt(Instant.now().plusMillis(EXPIRATION_ACCESS_TOKEN))
                .sign(this.getAlgorithm());
    }

    public String createRefreshToken(UserDetails userDetails) {
        return JWT.create()
                .withIssuer(ISSUER)
                .withSubject(userDetails.getUsername())
                .withExpiresAt(Instant.now().plusMillis(EXPIRATION_REFRESH_TOKEN))
                .sign(this.getAlgorithm());
    }
    /* omitted code */
}
````

**NOTA**

> El refresh token tiene que tener un tiempo superior al tiempo definido al access token, en nuestro caso le definimos
> 5 horas 1 minuto, además el refresh Token tiene menos datos expuestos que el access token y eso es porque solo lo
> usaremos para generar un nuevo access token.

También modificamos la clase de servicio **AuthService** donde preparamos la respuesta que contendrá, ahora, tanto el
accessToken como el refreshToken, para retornar al cliente.

````java

@Service
public class AuthService {
    /* omitted code */
    @Transactional(readOnly = true)
    private LoginResponseDTO loginResponse(String username) {
        Optional<User> userOptional = this.userRepository.findUserByUsername(username);
        UserDetails userDetails = new SecurityUser(userOptional.orElseThrow());
        String accessToken = this.jwtTokenProvider.createAccessToken(userDetails);
        String refreshToken = this.jwtTokenProvider.createRefreshToken(userDetails);
        LOG.info("Usuario logueado: {}", username);
        LOG.info("AccessToken: {}", accessToken);
        LOG.info("RefreshToken: {}", refreshToken);
        return new LoginResponseDTO(username, accessToken, refreshToken);
    }
    /* omitted code */
}
````

## Pruebas obtención accessToken y refreshToken

````bash
curl -i -X POST -H "Content-Type: application/json" -d "{\"username\":\"martin\", \"password\": \"12345\"}" http://localhost:8080/api/v1/auth/login
HTTP/1.1 200
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 03 Jul 2023 17:37:17 GMT

{
  "username":"martin",
  "accessToken":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJhdWQiOlsiVXNlciIsIk1hbmFnYW1lbnQiLCJQb3J0YWwiXSwiaWF0IjoxNjg4NDA1ODM3LCJzdWIiOiJtYXJ0aW4iLCJhdXRob3JpdGllcyI6WyJST0xFX1NVUEVSX0FETUlOIl0sImV4cCI6MTY4ODQwNzYzN30.08LAHOTIjUnH5TTGb-RKhSZsQuSHhOaEGMLH_tIKCFfxeq943Ge-JZ15U7FLpODwCjNWoAgFTYwdWpCHYAEkXQ",
  "refreshToken":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJzdWIiOiJtYXJ0aW4iLCJleHAiOjE2ODg0MjM4OTd9.4klsOQwrj7eEg78h-uzQPNNlhwA30mRaP6Lm_gQ0Qam23Jt6Hae94AGCQv7itLnicmOiIyZSmNcTVKPTvt1z6Q"
}
````

Payload del access token

````json
{
  "iss": "System",
  "aud": [
    "User",
    "Managament",
    "Portal"
  ],
  "iat": 1688405837,
  "sub": "martin",
  "authorities": [
    "ROLE_SUPER_ADMIN"
  ],
  "exp": 1688407637
}
````

Payload del refresh token

````json
{
  "iss": "System",
  "sub": "martin",
  "exp": 1688423897
}
````

Accediendo al endpoint de productos con el access token

````bash
curl -i -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJhdWQiOlsiVXNlciIsIk1hbmFnYW1lbnQiLCJQb3J0YWwiXSwiaWF0IjoxNjg4NDA1ODM3LCJzdWIiOiJtYXJ0aW4iLCJhdXRob3JpdGllcyI6WyJST0xFX1NVUEVSX0FETUlOIl0sImV4cCI6MTY4ODQwNzYzN30.08LAHOTIjUnH5TTGb-RKhSZsQuSHhOaEGMLH_tIKCFfxeq943Ge-JZ15U7FLpODwCjNWoAgFTYwdWpCHYAEkXQ" http://localhost:8080/api/v1/products
HTTP/1.1 200
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 03 Jul 2023 17:41:44 GMT

[
  {"id":1,"name":"Pc gamer","price":3500.0},
  {"id":2,"name":"Teclado inalámbrico","price":150.8},
  {"id":3,"name":"Mouse inalámbrico","price":99.9},
  {"id":4,"name":"Celular Samsung A7","price":5900.0}
]
````

Usando el refresh token para acceder al endpoint de productos

````bash
curl -i -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTeXN0ZW0iLCJzdWIiOiJtYXJ0aW4iLCJleHAiOjE2ODg0MjM4OTd9.4klsOQwrj7eEg78h-uzQPNNlhwA30mRaP6Lm_gQ0Qam23Jt6Hae94AGCQv7itLnicmOiIyZSmNcTVKPTvt1z6Q" http://localhost:8080/api/v1/products
HTTP/1.1 401
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Content-Length: 162
Date: Mon, 03 Jul 2023 17:44:10 GMT

{
  "path":"/error",
  "error":"Unauthorized",
  "message":"Full authentication is required to access this resource",
  "status":401,
  "ejemplo":"Caracteres con Perú Ñandú"
}
````

Como observamos, **no se puede usar un refresh token para poder acceder a un recurso protegido usándolo como access
token**

