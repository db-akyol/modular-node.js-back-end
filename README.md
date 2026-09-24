# Modular Node.js Backend

Rol ve yetki tabanlı bir REST API iskeleti. Express üzerine kurulu, katmanları birbirinden net şekilde ayrılmış (config / db / lib / routes) modüler bir backend mimarisi sunar. Kimlik doğrulama JWT + Passport ile, veri erişimi Mongoose modelleri ile, izlenebilirlik ise hem konsola (Winston) hem veritabanına (audit log) yazan çift katmanlı bir loglama altyapısı ile sağlanır. Yeni bir iş modülü eklemek için tek yapılması gereken `routes/` klasörüne bir dosya bırakmaktır; router otomatik olarak keşfedilip mount edilir.

![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.16-000000?style=flat&logo=express&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=flat&logo=mongodb&logoColor=white)
![Mongoose](https://img.shields.io/badge/Mongoose-8.7-880000?style=flat&logo=mongoose&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=flat&logo=jsonwebtokens&logoColor=white)
![Passport](https://img.shields.io/badge/Passport-34E27A?style=flat&logo=passport&logoColor=black)
![Winston](https://img.shields.io/badge/Winston-logging-231F20?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Özellikler

- **Otomatik router keşfi** — `routes/index.js`, klasördeki tüm `.js` dosyalarını okuyup dosya adıyla aynı isimde bir alt yol altında mount eder. Yeni modül eklemek için merkezi bir dosyayı düzenlemeye gerek yoktur.
- **JWT tabanlı kimlik doğrulama** — `passport-jwt` stratejisi ile `Authorization: Bearer <token>` başlığından token çözümlemesi; oturumsuz (stateless) çalışır.
- **Rol ve yetki (RBAC) altyapısı** — `Roles`, `UserRoles` ve `RolePrivileges` koleksiyonları ile kullanıcı → rol → yetki zinciri. Yetki kataloğu `config/role_privileges.js` içinde tek noktadan tanımlanır (USERS, ROLES, CATEGORIES, AUDITLOGS grupları).
- **İlk kullanıcı = SUPER_ADMIN** — `POST /api/users/register` yalnızca veritabanı boşken çalışır; ilk kullanıcıyı oluşturur ve ona otomatik olarak `SUPER_ADMIN` rolünü atar.
- **Standartlaştırılmış cevap zarfı** — Tüm uçlar `Response.succesResponse()` / `Response.errorResponse()` üzerinden aynı JSON şemasıyla cevap döner.
- **Özelleştirilmiş hata sınıfı** — `CustomError(code, message, description)` ile HTTP kodu taşıyan, katmanlar arası aktarılabilir hatalar.
- **Çift katmanlı loglama** — `LoggerClass` (Winston, konsol) ve `AuditLogs` (MongoDB `audit_logs` koleksiyonu) aynı imzayı paylaşır: `(email, location, proc_type, log)`.
- **Denetim kaydı sorgulama** — Tarih aralığı, `skip`/`limit` destekli audit log ucu.
- **Singleton desenli altyapı sınıfları** — `Database`, `AuditLogs` ve `LoggerClass` tek örnek (singleton) olarak kurgulanmıştır.
- **Model üzerinde iş kuralı** — Mongoose `loadClass` ile şemalara sınıf davranışı eklenir: `Users.validPassword()`, `Users.validateFieldsBeforeAuth()`, `Roles.deleteMany()` (rol silindiğinde bağlı yetkileri de temizler).
- **Merkezî HTTP kodu ve sabit yönetimi** — `config/Enum.js` içinde tüm HTTP kodları, log seviyeleri ve parola uzunluğu kuralı.
- **Şifre güvenliği** — `bcrypt` ile salt'lı hash; parola hiçbir zaman düz metin saklanmaz.

---

## Teknolojiler

| Paket | Sürüm | Kullanım amacı |
|---|---|---|
| express | ~4.16.1 | HTTP sunucusu ve routing |
| mongoose | ^8.7.2 | MongoDB ODM, şema ve model katmanı |
| passport | ^0.7.0 | Kimlik doğrulama çatısı |
| passport-jwt | ^4.0.1 | Bearer token çözümleme stratejisi |
| jwt-simple | ^0.5.6 | JWT üretimi (login) |
| bcrypt-nodejs | ^0.0.3 | Parola hash'leme ve doğrulama |
| winston | ^3.16.0 | Yapılandırılabilir konsol loglama |
| moment | ^2.30.1 | Audit log tarih aralığı hesaplamaları |
| is_js | ^0.9.0 | Tip ve format doğrulama (e-posta vb.) |
| dotenv | ^16.4.5 | `.env` dosyasından ortam değişkeni yükleme |
| ejs | ~2.6.1 | View motoru (hata ve karşılama sayfaları) |
| http-errors | ~1.6.3 | 404 ve HTTP hata nesneleri |
| morgan | ~1.9.1 | HTTP istek logları |
| cookie-parser | ~1.4.4 | Cookie ayrıştırma |
| debug | ~2.6.9 | Geliştirme zamanı hata ayıklama çıktısı |

> Not: `mongoose` ve `moment` kod tarafında kullanılmaktadır ancak `api/package.json` bağımlılık listesinde yer almaz. Kurulum adımlarında bu iki paket ayrıca kurulmalıdır (aşağıya bakın).

---

## Mimari

Proje, "her katman tek bir sorumluluk" ilkesine göre ayrılmıştır. Bir HTTP isteğinin izlediği yol:

```
İstek
  │
  ▼
app.js ──────────────► morgan / express.json / cookieParser / static
  │
  ▼
routes/index.js ─────► klasörü tarar, her .js dosyasını /api/<dosya-adı> altına mount eder
  │
  ▼
routes/<modül>.js ───► router.all("*", auth.authenticate())  → JWT doğrulaması
  │                    gövde doğrulama (is_js + CustomError)
  │
  ├──► db/models/*.js ─► Mongoose şeması + loadClass ile iş kuralları
  │
  ├──► lib/AuditLogs.js ─► audit_logs koleksiyonuna kalıcı denetim kaydı
  ├──► lib/logger/ ───────► Winston üzerinden konsol logu
  │
  ▼
lib/Response.js ─────► tek tip başarı / hata zarfı
  │
  ▼
Cevap (JSON)
```

### Katmanlar ve sorumlulukları

**`config/` — Yapılandırma katmanı**
Uygulamanın tüm sabitleri ve ortam bağımlı ayarları burada toplanır; başka hiçbir katman `process.env`'e doğrudan dokunmaz.
- `index.js` — Ortam değişkenlerini okuyup makul varsayılanlarla dışa açar (`LOG_LEVEL`, `CONNECTION_STRING`, `PORT`, `JWT.SECRET`, `JWT.EXPIRE_TIME`).
- `Enum.js` — HTTP durum kodları, log seviyeleri, `PASS_LENGTH`, `SUPER_ADMIN` sabiti. Kodda hiçbir yerde "sihirli sayı" bırakmamayı hedefler.
- `role_privileges.js` — Yetki grupları (`privGroups`) ve yetki anahtarları (`privileges`) kataloğu. RBAC'in tek doğruluk kaynağıdır ve `GET /api/roles/role_privileges` ucundan istemciye açılır.

**`db/` — Veri erişim katmanı**
- `Database.js` — Mongoose bağlantısını yöneten singleton sınıf. Bağlantı `bin/www` içinde sunucu dinlemeye başladığında kurulur; başarısızlık durumunda süreç kontrollü şekilde sonlanır.
- `db/models/` — Her koleksiyon için bir dosya. Şema tanımının yanında `schema.loadClass(...)` ile davranış eklenir; böylece iş kuralları route'lara sızmak yerine modelde kalır:
  - `Users` — `validPassword()` (bcrypt karşılaştırma) ve statik `validateFieldsBeforeAuth()`.
  - `Roles` — `deleteMany()` override'ı; rol silinirken ilişkili `RolePrivileges` kayıtlarını da temizleyerek yetim kayıt oluşmasını engeller.
  - `UserRoles`, `RolePrivileges` — kullanıcı-rol ve rol-yetki ilişki tabloları.
  - `Categories` — örnek iş modülü.
  - `AuditLogs` — `log` alanı `Mixed` tipinde, serbest yapıda denetim kaydı.
  - Tüm şemalarda `versionKey: false` ve `created_at` / `updated_at` adlandırmalı timestamp'ler kullanılır.

**`lib/` — Altyapı / servis katmanı**
Route'ların ihtiyaç duyduğu ortak yetenekleri sağlar; HTTP'den bağımsız, yeniden kullanılabilir birimlerdir.
- `auth.js` — `passport-jwt` stratejisini kurar. Token içindeki `id` ile kullanıcıyı bulur, rollerini ve rollerden türeyen yetki listesini çözer ve `req.user` nesnesine (`id`, `email`, `first_name`, `last_name`, `roles`) yerleştirir.
- `Error.js` — `Error`'dan türeyen `CustomError`; HTTP kodu, mesaj ve açıklamayı birlikte taşır.
- `Response.js` — Başarı ve hata cevaplarını tek şemaya indirger. `CustomError`, MongoDB `E11000` (benzersizlik ihlali → 409 Conflict) ve beklenmeyen hataları (→ 500) ayırt eder.
- `AuditLogs.js` — `info/warn/error/debug/verbose/http` metotlarıyla denetim kaydını veritabanına yazan singleton. Yazma işlemi `#saveToDB` private metodunda kapsüllenmiştir.
- `logger/logger.js` — Winston transport ve format yapılandırması (timestamp + `email` / `location` / `procType` alanlarıyla okunabilir satır çıktısı).
- `logger/LoggerClass.js` — Winston'ı saran, `AuditLogs` ile birebir aynı imzaya sahip singleton facade. Konsol ve veritabanı loglaması böylece çağrı tarafında simetrik kalır.

**`routes/` — Sunum (HTTP) katmanı**
- `index.js` — `fs.readdirSync` ile klasörü tarar; `index.js` dışındaki her `.js` dosyasını `/<dosya-adı>` yoluna mount eder. `app.js` bu router'ı `/api` altına bağladığından, `routes/categories.js` otomatik olarak `/api/categories` olur. Yeni modül = yeni dosya.
- Modül router'ları — İstek gövdesi doğrulaması, model çağrıları ve log tetikleme burada yapılır. Her modül `router.all("*", auth.authenticate())` satırıyla kendi koruma sınırını kendisi çizer; `users.js` bu satırı bilinçli olarak `register` ve `auth` uçlarının *altına* koyarak bu iki ucu açık bırakır.

**`app.js` / `bin/www` — Uygulama ve süreç katmanı**
- `app.js` — Middleware zinciri, EJS view motoru, statik dosya servisi, `/api` mount'u, 404 yakalama ve merkezî hata işleyici.
- `bin/www` — HTTP sunucusunu oluşturur, port normalizasyonu ve `EACCES` / `EADDRINUSE` hatalarını anlamlı mesajlarla ele alır, sunucu dinlemeye başladığında veritabanı bağlantısını başlatır.

---

## API Endpoint'leri

Tüm uçların ön eki `/api`'dir. Kimlik doğrulama gerektiren uçlar `Authorization: Bearer <token>` başlığı bekler.

### Kullanıcılar — `/api/users`

| Metot | Yol | Açıklama | Kimlik doğrulama |
|---|---|---|---|
| POST | `/api/users/register` | İlk kullanıcıyı oluşturur ve `SUPER_ADMIN` rolünü atar. Veritabanında kullanıcı varsa çalışmaz. | Hayır |
| POST | `/api/users/auth` | E-posta ve parola ile giriş; JWT token ve temel kullanıcı bilgisi döner. | Hayır |
| GET | `/api/users/` | Tüm kullanıcıları listeler. | Evet |
| POST | `/api/users/add` | Yeni kullanıcı oluşturur ve `roles` dizisindeki rolleri atar. | Evet |
| POST | `/api/users/update` | `_id` ile kullanıcıyı ve rol atamalarını günceller. | Evet |
| POST | `/api/users/delete` | `_id` ile kullanıcıyı ve ilişkili rol kayıtlarını siler. | Evet |

### Roller — `/api/roles`

| Metot | Yol | Açıklama | Kimlik doğrulama |
|---|---|---|---|
| GET | `/api/roles/` | Tüm rolleri listeler. | Evet |
| POST | `/api/roles/add` | `role_name` ve `permissions` dizisi ile rol oluşturur. | Evet |
| POST | `/api/roles/update` | `_id` ile rolü ve yetkilerini günceller. | Evet |
| POST | `/api/roles/delete` | `_id` ile rolü ve bağlı yetkilerini siler. | Evet |
| GET | `/api/roles/role_privileges` | Sistemdeki yetki gruplarını ve yetki kataloğunu döner. | Evet |

### Kategoriler — `/api/categories`

| Metot | Yol | Açıklama | Kimlik doğrulama |
|---|---|---|---|
| GET | `/api/categories/` | Tüm kategorileri listeler. | Evet |
| POST | `/api/categories/add` | `name` alanı ile kategori oluşturur; audit log ve konsol logu yazar. | Evet |
| POST | `/api/categories/update` | `_id` ile kategoriyi günceller; audit log yazar. | Evet |
| POST | `/api/categories/delete` | `_id` ile kategoriyi siler; audit log yazar. | Evet |

### Denetim Kayıtları — `/api/auditlogs`

| Metot | Yol | Açıklama | Kimlik doğrulama |
|---|---|---|---|
| POST | `/api/auditlogs/` | Denetim kayıtlarını sorgular. Gövde: `begin_date`, `end_date`, `skip` (varsayılan 0), `limit` (varsayılan 500). Tarih verilmezse son 1 günün kayıtları döner. | Evet |

### Cevap formatı

Başarılı:

```json
{
  "code": 200,
  "data": { }
}
```

Hatalı:

```json
{
  "code": 400,
  "error": {
    "message": "Validation Error!",
    "description": "email field must be an email format"
  }
}
```

---

## Ortam Değişkenleri

`api/.env.example` dosyasında tanımlı değişkenler:

| Değişken | Zorunlu | Varsayılan | Açıklama |
|---|---|---|---|
| `CONNECTION_STRING` | Evet | `mongodb://localhost:27017` | MongoDB bağlantı adresi. |
| `LOG_LEVEL` | Hayır | `debug` | Winston log seviyesi: `error` \| `warn` \| `info` \| `debug`. |

`config/index.js` tarafından ayrıca okunan, `.env.example`'da yer almayan değişkenler:

| Değişken | Zorunlu | Varsayılan | Açıklama |
|---|---|---|---|
| `PORT` | Hayır | `3000` | HTTP sunucusunun dinleyeceği port. |
| `TOKEN_EXPIRE_TIME` | Hayır | `86400` (24 saat) | JWT geçerlilik süresi (saniye). |
| `NODE_ENV` | Hayır | — | `production` dışındaki değerlerde `.env` dosyası yüklenir. |

> Güvenlik notu: JWT imzalama anahtarı (`JWT.SECRET`) şu anda `config/index.js` içinde sabit olarak tanımlıdır. Üretim ortamına çıkmadan önce bu değerin bir ortam değişkenine taşınması gerekir. `.env` dosyası `.gitignore` ile sürüm kontrolünün dışında tutulmuştur.

---

## Kurulum

Gereksinimler: Node.js 18+ ve çalışır durumda bir MongoDB örneği.

```bash
# 1. Depoyu klonlayın
git clone <repo-url>
cd modular-node.js-back-end/api

# 2. Bağımlılıkları kurun
npm install

# 3. package.json'da listelenmeyen ancak kod tarafında kullanılan paketler
npm install mongoose moment

# 4. Ortam değişkenlerini hazırlayın
cp .env.example .env
```

Ardından `.env` dosyasını kendi MongoDB bağlantı adresinizle düzenleyin:

```env
CONNECTION_STRING=mongodb://localhost:27017/veritabani-adi
LOG_LEVEL=info
```

---

## Çalıştırma

```bash
cd api
npm start
```

Sunucu varsayılan olarak `http://localhost:3000` adresinde ayağa kalkar. Konsolda `db connecting` ve `db connected` satırlarını görmeniz bağlantının kurulduğu anlamına gelir.

İlk kurulumdan sonra izlenecek akış:

```bash
# 1) İlk kullanıcıyı (SUPER_ADMIN) oluştur
curl -X POST http://localhost:3000/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@ornek.com","password":"Parola123","first_name":"Ad","last_name":"Soyad"}'

# 2) Giriş yap ve token al
curl -X POST http://localhost:3000/api/users/auth \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@ornek.com","password":"Parola123"}'

# 3) Korumalı bir ucu çağır
curl http://localhost:3000/api/categories \
  -H "Authorization: Bearer <token>"
```

---

## Proje Yapısı

```
modular-node.js-back-end/
├── api/
│   ├── bin/
│   │   └── www                     # Sunucu başlatma, port yönetimi, DB bağlantı tetikleme
│   ├── config/
│   │   ├── Enum.js                 # HTTP kodları, log seviyeleri, sabitler
│   │   ├── index.js                # Ortam değişkeni okuma ve varsayılanlar
│   │   └── role_privileges.js      # Yetki grupları ve yetki kataloğu (RBAC)
│   ├── db/
│   │   ├── Database.js             # Mongoose bağlantısı (singleton)
│   │   └── models/
│   │       ├── AuditLogs.js        # Denetim kaydı şeması
│   │       ├── Categories.js       # Örnek iş modülü şeması
│   │       ├── RolePrivileges.js   # Rol-yetki ilişkisi
│   │       ├── Roles.js            # Rol şeması + cascade delete
│   │       ├── UserRoles.js        # Kullanıcı-rol ilişkisi
│   │       └── Users.js            # Kullanıcı şeması + parola doğrulama
│   ├── lib/
│   │   ├── auth.js                 # passport-jwt stratejisi ve yetki çözümleme
│   │   ├── AuditLogs.js            # Veritabanına denetim logu (singleton)
│   │   ├── Error.js                # CustomError sınıfı
│   │   ├── Response.js             # Tek tip başarı/hata cevap zarfı
│   │   └── logger/
│   │       ├── logger.js           # Winston yapılandırması
│   │       └── LoggerClass.js      # Winston facade (singleton)
│   ├── routes/
│   │   ├── index.js                # Otomatik router keşfi ve mount
│   │   ├── auditlogs.js            # /api/auditlogs
│   │   ├── categories.js           # /api/categories
│   │   ├── roles.js                # /api/roles
│   │   └── users.js                # /api/users
│   ├── public/
│   │   └── stylesheets/style.css
│   ├── views/
│   │   ├── error.ejs
│   │   └── index.ejs
│   ├── app.js                      # Express uygulaması ve middleware zinciri
│   ├── package.json
│   └── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

---

## Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır.

Copyright (c) 2025 Deniz Akyol
