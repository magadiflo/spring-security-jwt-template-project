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
