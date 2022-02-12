## 1、登入注册流程
#### 1-1 注册流程
* 提交注册信息 --> 参数校验 --> ⼊库 --> 注册成功
#### 1-2 登录流程
* 提交登录信息 --> 参数校验 --> 查询数据库 --> 登陆成功 --> 下发Token

## 2、⽤户认证
#### 2-1 前言
* HTTP 是⼀个⽆状态的协议，⼀次请求结束后，下次在发送服务器就不知道这个请求是谁发来的了（同⼀个 IP 不代表同⼀个⽤户），在 Web 应⽤中，⽤户的认证和鉴权是⾮常重要的⼀环，实践中有多种可⽤⽅案，并且各有千秋。

#### 2-2 Cookie- Session 认证模式
* 在 Web 应⽤发展的初期，⼤部分采⽤基于Cookie-Session 的会话管理⽅式，逻辑如下。
  * 客户端使⽤⽤户名、密码进⾏认证
  * 服务端验证⽤户名、密码正确后⽣成并存储 Session，将 SessionID 通过 Cookie 返回给客户端
  * 客户端访问需要认证的接⼝时在 Cookie 中携带 SessionID
  * 服务端通过 SessionID 查找 Session 并进⾏鉴权，返回给客户端需要的数据
#### 2-3 基于 Session 的⽅式存在多种问题
* 服务端需要存储 Session，并且由于 Session 需要经常快速查找，通常存储在内存或内存数据库中，同时在线⽤户较多时需要占⽤⼤量的服务器资源。
* 当需要扩展时，创建 Session 的服务器可能不是验证 Session 的服务器，所以还需要将所有Session单独存储并共享。
* 由于客户端使⽤ Cookie 存储 SessionID，在跨域场景下需要进⾏兼容性处理，同时这种⽅式也难以防范 **CSRF** 攻击。
#### 3、Token 认证模式
#### 3-1 前言
* 鉴于基于 Session 的会话管理⽅式存在上述多个缺点，基于 Token 的⽆状态会话管理⽅式诞⽣了，所谓⽆状态，就是服务端可以不再存储信息，甚⾄是不再存储session

#### 3-2 Token 认证模式
* 逻辑如下
  * 客户端使⽤⽤户名、密码进⾏认证
  * 服务端验证⽤户名、密码正确后⽣成 Token 返回给客户端
  * 客户端保存 Token，访问需要认证的接⼝时在 URL 参数或 HTTP Header 中加⼊ Token
  * 服务端通过解码 Token 进⾏**鉴权**，返回给客户端需要的数据
* 基于Token的会话管理⽅式有效解决了基于 Session 的会话管理⽅式带来的问题。
服务端不需要存储和⽤户鉴权有关的信息，鉴权信息会被加密到 Token 中，服务端只需要读取Token中包含的鉴权信息即可，避免了共享Session导致的不易扩展问题，不需要依赖 Cookie，有效避免 Cookie 带来的 CSRF 攻击问题
使⽤ CORS 可以快速解决跨域问题

## 4、JWT
#### 4-1 前言
* JWT 是 JSON Web Token 的缩写，是为了在⽹络应⽤环境间传递声明⽽执⾏的⼀种基于JSON的开放标准（(RFC 7519)。JWT 本身没有定义任何技术实现，它只是定义了⼀种基于 Token 的会话管理的规则，涵盖 Token 需要包含的标准内容和 Token 的⽣成过程，特别适⽤于分布式站点的单点登录（SSO）场景。

#### 4-2 JWT Token格式
* 它是由 . 分隔的三部分组成，这三部分依次是：
    * 头部（Header）
    * 负载（Payload）
    * 签名（Signature）
* 头部和负载以 JSON 形式存在，这就是 JWT 中的 JSON，三部分的内容都分别单独经过了 Base64 编码，以 . 拼接成⼀个 JWT Token。
* Header
  * JWT 的 Header 中存储了所使⽤的**加密算法**和 Token **类型**。
```
{
 "alg": "HS256",
 "typ": "JWT"
}
```
* Payload
  * Payload 表示负载，也是⼀个 JSON 对象，JWT 规定了7个官⽅字段供选⽤，
  * 除了官⽅字段，开发者也可以⾃⼰指定字段和内容（如用户id，用户名）
  * 注意，JWT 默认是不加密的，任何⼈都可以读到，所以不要把秘密信息放在这个部分。这个 JSON 对象也要使⽤ Base64URL 算法转成字符串。
```
// 官方字段
iss (issuer)：签发⼈
exp (expiration time)：过期时间
sub (subject)：主题
aud (audience)：受众
nbf (Not Before)：⽣效时间
iat (Issued At)：签发时间
jti (JWT ID)：编号

// 自定义
{
 "sub": "1234567890",
 "name": "John Doe",
 "admin": true
}
```
* Signature
  * Signature 部分是对前两部分的签名，防⽌数据篡改。
  * ⾸先，需要指定⼀个密钥（secret）。这个密钥只有服务器才知道，不能泄露给⽤户。然后，使⽤Header ⾥⾯指定的签名算法生成签名（这个签名用于核对该token是否有效）

#### 4-3 JWT优点
* JWT 拥有基于 Token 的会话管理⽅式所拥有的⼀切优势，不依赖 Cookie，使得其可以防⽌ CSRF 攻击，也能在禁⽤ Cookie 的浏览器环境中正常运⾏。
* ⽽ JWT 的最⼤优势是服务端不再需要存储 Session，使得服务端认证鉴权业务可以⽅便扩展，避免存储Session 所需要引⼊的 Redis 等组件，降低了系统架构复杂度。
  
#### 4-4 JWT缺点
* 优点，但这也是 JWT 最⼤的劣势，由于有效期存储在 Token 中，JWT Token ⼀旦签发，就会在有效期内⼀直可⽤，**⽆法在服务端废⽌**，当⽤户进⾏登出操作，只能依赖客户端删除掉本地存储的 JWT Token，如果需要禁⽤⽤户，单纯使⽤ JWT 就⽆法做到
了。

## 5、基于jwt实现认证 refresh token
* 前⾯讲的 Token，都是 Access Token，也就是访问资源接⼝时所需要的 Token，还有另外⼀种Token，Refresh Token，通常情况下，Refresh Token 的有效期会⽐较⻓，⽽ Access Token 的有效期⽐较短，当 Access Token 由于过期⽽失效时，使⽤ Refresh Token 就可以获取到新的 Access Token，如果 Refresh Token 也失效了，⽤户就只能重新登录了。
* 在 JWT 的实践中，引⼊ Refresh Token，将会话管理流程改进如下
  * 客户端使⽤⽤户名密码进⾏认证
  * 服务端⽣成有效时间较短的 Access Token（例如 10 分钟），和有效时间较⻓的 RefreshToken（例如 7 天）
  * 客户端访问**需要认证**的接⼝时，携带 Access Token，如果 Access Token 没有过期，服务端鉴权后返回给客户端需要的数据
  * 如果携带 Access Token 访问需要认证的接⼝时鉴权失败（例如返回 401 错误），则客户端使⽤Refresh Token 向**刷新接⼝**申请新的 Access Token
  * 如果 Refresh Token 没有过期，服务端向客户端下发新的 Access Token
  * 客户端使⽤新的 Access Token 访问需要认证的接⼝

* **注意点,后端需要对外提供⼀个刷新Token的接⼝，前端需要实现⼀个当Access Token过期时⾃动请求刷新Token接⼝获取新Access Token的拦截器。**
## 6、gin框架使⽤jwt

* 鉴权中间件开发
```
const (
 ContextUserIDKey = "userID"
)

// JWTAuthMiddleware 基于JWT的认证中间件
func JWTAuthMiddleware() func(c *gin.Context) {
    return func(c *gin.Context) {
    // 客户端携带Token有三种⽅式 1.放在请求头 2.放在请求体 3.放在URI
    // 这⾥假设Token放在Header的中
    // 这⾥的具体实现⽅式要依据你的实际业务情况决定
    authHeader := c.Request.Header.Get("Auth")
    if authHeader == "" {
        ResponseErrorWithMsg(c, CodeInvalidToken, "请求头缺少Auth Token")
        c.Abort()
        return
    }
    mc, err := utils.ParseToken(authHeader)
    if err != nil {
        ResponseError(c, CodeInvalidToken)
        c.Abort()
        return
    }
    // 将当前请求的username信息保存到请求的上下⽂c上
    c.Set(ContextUserIDKey, mc.UserID)
    c.Next() // 后续的处理函数可以⽤过c.Get("userID")来获取当前请求的⽤户信息
    }
}
```
* GenToken
```
// GenToken ⽣成access token 和 refresh token
func GenToken(userID int64) (aToken, rToken string, err error) {
    // 创建⼀个我们⾃⼰的声明
    c := MyClaims{
        userID, // ⾃定义字段
        jwt.StandardClaims{
            ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(), // 过期时间
            Issuer: "bluebell", // 签发⼈
        },
    }
    // 加密并获得完整的编码后的字符串token
    aToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256,c).SignedString(mySecret)
    // refresh token 不需要存任何⾃定义数据
    rToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, 
        jwt.StandardClaims{
            ExpiresAt: time.Now().Add(time.Second * 30).Unix(), // 过期时间
            Issuer: "bluebell", // 签发⼈
        }
    ).SignedString(mySecret)
    // 使⽤指定的secret签名并获得完整的编码后的字符串token
    return
}
```
* ParseToken
```
// ParseToken 解析JWT
func ParseToken(tokenString string) (claims *MyClaims, err error) {
    // 解析token
    var token *jwt.Token
    claims = new(MyClaims)
    token, err = jwt.ParseWithClaims(tokenString, claims, keyFunc)
    if err != nil {
        return
    }
    if !token.Valid { // 校验token
        err = errors.New("invalid token")
    }
    return
}
```
* refresh
```
// RefreshToken 刷新AccessToken
func RefreshToken(aToken, rToken string) (newAToken, newRToken string,err error) {
    // refresh token⽆效直接返回
    if _, err = jwt.Parse(rToken, keyFunc); err != nil {
        return
    }
    
    // 从旧access token中解析出claims数据
    var claims MyClaims
    _, err = jwt.ParseWithClaims(aToken, &claims, keyFunc)
    v, _ := err.(*jwt.ValidationError)
    
    // 当access token是过期错误 并且 refresh token没有过期时就创建⼀个新的access token
    if v.Errors == jwt.ValidationErrorExpired {
        return GenToken(claims.UserID)
    }
    return
}
```

## 7、基于jwt实现 限制多点登入
* 实现方式
  * 还没有登入的用户提交登入请求，服务器获得username，password
  * 服务器鉴权之后，生成token，并将token与username相关联持久化
  * 服务器返回token，用户保存token
  * 异地登入的时候，服务器根据username，生成新的token，更新username与token相对应的表
  * 本地用户刷新页面（携带token发送给服务器），但是，这个token已经是旧的了（时间没有过期），因为刚刚被一点登入的更新了token-username了
* 有点类似与cookie-session的方式，持久化


## 8、Token 认证的优势
* 1.无状态
token 自身包含了身份验证所需要的所有信息，使得我们的服务器不需要存储 Session 信息，这显然增加了系统的可用性和伸缩性，大大减轻了服务端的压力。但是，也正是由于 token 的无状态，也导致了它最大的缺点：当后端在token 有效期内废弃一个 token 或者更改它的权限的话，不会立即生效，一般需要等到有效期过后才可以。另外，当用户 Logout 的话，token 也还有效。除非，我们在后端增加额外的处理逻辑。

* 2.有效避免了CSRF 攻击
一般情况下我们使用 JWT 的话，在我们登录成功获得 token 之后，一般会选择存放在  local storage 中。然后我们在前端通过某些方式会给每个发到后端的请求加上这个 token,这样就不会出现 CSRF 漏洞的问题。因为，即使有个你点击了非法链接发送了请求到服务端，这个非法请求是不会携带 token 的，所以这个请求将是非法的。
>但是这样会存在  XSS 攻击中被盗的风险，为了避免 XSS 攻击，你可以选择将 token 存储在标记为httpOnly  的cookie 中。但是，这样又导致了你必须自己提供CSRF保护。
>具体采用上面哪两种方式存储 token 呢，大部分情况下存放在  local storage 下都是最好的选择，某些情况下可能需要存放在标记为httpOnly  的cookie 中会更好。

* 3.适合移动端应用
使用 Session 进行身份认证的话，需要保存一份信息在服务器端，而且这种方式会依赖到 Cookie（需要 Cookie 保存 SessionId），所以不适合移动端。但是，使用 token 进行身份认证就不会存在这种问题，因为只要 token 可以被客户端存储就能够使用，而且 token 还可以跨语言使用。

* 4.单点登录友好
使用 Session 进行身份认证的话，实现单点登录，需要我们把用户的 Session 信息保存在一台电脑上，并且还会遇到常见的 Cookie 跨域的问题。但是，使用 token 进行认证的话， token 被保存在客户端，不会存在这些问题。

## 9、Token 认证常见问题以及解决办法


#### 9-1 注销登录等场景下 token 还有效
*  1.注销登录等场景下 token 还有效，与之类似的具体相关场景有：
    * 退出登录;
    * 修改密码;
    * 服务端修改了某个用户具有的权限或者角色；
    * 用户的帐户被删除/暂停。
    * 用户由管理员注销；
 * 这个问题不存在于 Session  认证方式中，因为在  Session  认证方式中，遇到这种情况的话服务端删除对应的 Session 记录即可。但是，使用 token 认证的方式就不好解决了。我们也说过了，token 一旦派发出去，如果后端不增加其他逻辑的话，它在失效之前都是有效的。
* 那么，我们如何解决这个问题呢？查阅了很多资料，总结了下面几种方案

* 解决方案：
  * 1、**token 存入内存数据库** ：将 token 存入 DB 中，redis 内存数据库在这里是是不错的选择。如果需要让某个 token 失效就直接从 redis 中删除这个 token 即可。但是，这样会导致每次使用 token 发送请求都要先从 DB 中查询 token 是否存在的步骤，**而且违背了 JWT 的无状态原则。**
  * 2、黑名单机制：和上面的方式类似，使用内存数据库比如 redis 维护一个黑名单，如果想让某个 token 失效的话就直接将这个 token 加入到 黑名单 即可。然后，每次使用 token 进行请求的话都会先判断这个 token 是否存在于黑名单中。
  * 3、**修改密钥 (Secret)** : 我们为每个用户都创建一个专属密钥，如果我们想让某个 token 失效，我们直接修改对应用户的密钥即可。但是，这样相比于前两种引入内存数据库带来了危害更大，比如：
    * 1、如果服务是分布式的，则每次发出新的 token 时都必须在多台机器同步密钥。为此，你需要将必须将机密存储在数据库或其他外部服务中，这样和 Session 认证就没太大区别了。
    * 2、如果用户同时在两个浏览器打开系统，或者在手机端也打开了系统，如果它从一个地方将账号退出，那么其他地方都要重新进行登录，这是不可取的。
  * 4、保持令牌的**有效期限短**并经常轮换 ：很简单的一种方式。但是，会导致用户登录状态不会被持久记录，而且需要用户经常登录。
* **对于修改密码后 token 还有效问题的解决还是比较容易的，说一种我觉得比较好的方式：使用用户的密码的哈希值对 token 进行签名。因此，如果密码更改，则任何先前的令牌将自动无法验证。（自检查）**

#### 9-2 token 的续签问题
* token 有效期一般都建议设置的不太长，那么 token 过期后如何认证，如何实现动态刷新 token，避免用户经常需要重新登录？
>我们先来看看在 Session 认证中一般的做法：假如 session 的有效期30分钟，如果 30 分钟内用户有访问，就把 session 有效期被延长30分钟。
* 解决方案
  * 1、类似于 Session 认证中的做法：这种方案满足于大部分场景。假设服务端给的 token 有效期设置为30分钟，服务端每次进行校验时，如果发现 token 的有效期马上快过期了，服务端就重新生成 token 给客户端。客户端每次请求都检查新旧token，如果不一致，则更新本地的token。这种做法的问题是仅仅在快过期的时候请求才会更新 token ,对客户端不是很友好。
  * 2、每次请求都返回新 token :这种方案的的思路很简单，但是，很明显，开销会比较大。
  * 3、token 有效期设置到半夜 ：这种方案是一种折衷的方案，保证了大部分用户白天可以正常登录，适用于对安全性要求不高的系统。
  * 4、用户登录返回两个 token ：第一个是 acessToken ，它的过期时间 token 本身的过期时间比如半个小时，另外一个是 refreshToken 它的过期时间更长一点比如为1天。客户端登录后，将 accessToken和refreshToken 保存在本地，每次访问将 accessToken 传给服务端。服务端校验 accessToken 的有效性，如果过期的话，就将 refreshToken 传给服务端。如果有效，服务端就生成新的 accessToken 给客户端。否则，客户端就重新登录即可。该方案的不足是：
    * 1⃣️需要客户端来配合；
    * 2⃣️用户注销的时候需要同时保证两个  token 都无效；
    * 3⃣️重新请求获取 token  的过程中会有短暂 token 不可用的情况（可以通过在客户端设置定时器，当accessToken 快过期的时候，提前去通过 refreshToken 获取新的accessToken）。
## 10 总结
* JWT 最适合的场景是不需要服务端保存用户状态的场景，如果考虑到 token 注销和 token 续签的场景话，没有特别好的解决方案，大部分解决方案都给 token 加上了状态，这就有点类似 Session 认证了。