---
name: securekit
description: Add application-level encryption to a Python or Node.js project with the securekit library in this repository. Use it to encrypt database fields (including SQLAlchemy models), search encrypted columns, make rows tamper-evident, verify signed webhooks, hash passwords with Argon2id, keep application secrets in an encrypted versioned vault, give each user a server-blind vault, and scan a codebase for unprotected secrets and data. Trigger on tasks about storing PII, passwords, API keys, tokens or secrets, "encrypt this", "make this app secure", key rotation, or removing secrets from a repo.
---

# securekit: integration skill for AI agents and production teams

You are adding encryption to someone's application. securekit is a **thin layer over vetted primitives** (AES-256-GCM, HMAC-SHA256,
HKDF, Argon2id from `cryptography` / `argon2-cffi` / `node:crypto`). It contains no cryptography of its own. Python and Node.js
produce and read identical tokens, seals, vault files and password hashes (`SPEC.md`).

**Building or reviewing a whole application?** This skill is only the *data-protection* part. Start with `../secure-app/SKILL.md`, which covers the threat model, authentication,
authorization, injection and web attacks, operations and delivery, and calls back here for encryption, secrets and password hashing.

**Say plainly to the user:** securekit is not independently audited and is not a compliance certification. It protects data
*inside the application*. TLS, disk encryption, KMS/HSM custody and backups are still needed: `docs/ENCRYPTION-MAP.md` lists every place and
who covers it.

Paths in this note (`python/`, `node/`, `docs/`, `SPEC.md`) are relative to the `securekit/` folder of this repository. Recipes use names from the
user's own app (`user`, `request`, `db`, `session`) as placeholders; everything from `securekit` is real API and was run as written.

## 1. Pick the right tool

| The task says... | Use | Python | Node.js |
|---|---|---|---|
| store a sensitive value in a database column | field encryption | `FieldCipher(ring).encrypt(v, context("users","ssn",row_id))` | `new FieldCipher(ring).encrypt(v, context('users','ssn',rowId))` |
| the same, with SQLAlchemy | model integration | `securekit.orm.SecureModels` + `EncryptedText` | n/a (use `FieldCipher`) |
| look rows up by an encrypted value (email) | blind index | `BlindIndexer(ring).index(v, context("users","email"))`, `.candidates(...)` for queries | same names, camelCase |
| detect edits to important rows | record seal | `RecordSealer(ring).seal(record, ctx)` / `.verify(...)` | same |
| verify or sign webhooks | request signing | `Signer(ring).verify(body, header)` | same |
| store user passwords | Argon2id | `hash_password`, `verify_password`, `needs_rehash` | `hashPassword`, `verifyPassword`, `needsRehash` |
| remove API keys / DB passwords from code and `.env` | **app secrets vault** | `securekit.vault.Vault` or `python -m securekit vault ...` | `Vault` or `node bin/securekit.js vault ...` |
| data the server must not be able to read | **per-user vault** | `securekit.uservault.UserVault` | `UserVault` |
| session ids, reset tokens | random tokens | `random_token()` | `randomToken()` |
| find what is unprotected in a codebase | scanner | `python -m securekit scan PATH` | (same tool, language independent) |
| a network secrets service with logins and policies | **not securekit** | use OpenBao / HashiCorp Vault / cloud secret manager; feed their data keys to `Keyring` | same |

## 2. Fast path (about an hour for one service)

1. **Install** (this repo is the source): `pip install -e securekit/python` (add `sqlalchemy` for the ORM layer, 2.0.x),
   `npm install ./securekit/node` (Node 24.7+ for Argon2id). Or copy the folder into the project so it is versioned with it.
2. **Make the keyring** once per environment: `python -m securekit genkeyring k1` prints JSON. Put it in the platform secret store
   and expose it to the app as `SECUREKIT_KEYRING`. Never commit it, never put it in an image or the database it protects.
3. **Scan first** to see the starting point: `python -m securekit scan . --fail-on never`. Fix `critical` and `high` items.
4. **Move secrets into the vault**: create it with `securekit vault init`, `printf %s "$VALUE" | securekit vault put NAME`
   for each, then read them at startup (recipe 3.3). Delete the old copies and **rotate anything that was ever in git**.
5. **Encrypt the sensitive columns** (recipes 3.1, 3.2). Decide the `context` for each column before writing data (it cannot change later).
6. **Replace password hashing** with Argon2id (recipe 3.5) and re-hash on login using `needs_rehash`.
7. **Add the checks to CI**: the test suites you wrote plus `python -m securekit scan . --fail-on high`.
8. **Write down** who owns the keyring, the rotation schedule and the restore procedure (`docs/RUNBOOK.md`).

## 3. Recipes

### 3.1 Encrypt a field (Python)

```python
from securekit import Keyring, FieldCipher, context, InvalidToken
ring = Keyring.from_env()                      # SECUREKIT_KEYRING
cipher = FieldCipher(ring)

token = cipher.encrypt("123-45-6789", context("users", "ssn", user.id))   # store this string
ssn = cipher.decrypt_str(token, context("users", "ssn", user.id))          # raises InvalidToken if moved to another row/column
```

```js
const { Keyring, FieldCipher, context } = require('securekit');
const cipher = new FieldCipher(Keyring.fromEnv());
const token = cipher.encrypt('123-45-6789', context('users', 'ssn', user.id));
const ssn = cipher.decryptString(token, context('users', 'ssn', user.id));
```

Use client-generated ids (UUIDs) so the id exists before you encrypt. Add a column for the token (TEXT) and another for a blind index if you search it.

### 3.2 SQLAlchemy 2.0 (Python), automatic

```python
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(EncryptedText)
    email_idx: Mapped[Optional[str]] = mapped_column(String(100), index=True)   # blind index, maintained for you
    role: Mapped[str] = mapped_column(String(20))
    row_seal: Mapped[Optional[str]] = mapped_column(String(200))

secure = SecureModels(Keyring.from_env())
secure.register(User, encrypted=["email"], blind={"email_idx": "email"},
                seal=SealSpec("row_seal", ["id", "role"]), assign_id=lambda: str(uuid.uuid4()))

user = session.scalars(select(User).where(secure.blind_filter(User, "email", "a@x.comŠJJK›Û™J
B˜‚”[\ÈH^Y\ˆ[™›Ü˜Ù\ÎˆYÈ^\İ™Y›Ü™HH›\Ú
]]Ú[˜Ü™[Y[[È˜Z\ÙJKÙX[YÛÛ[[œÈ\™HÙ]^XÚ]H
›ÈÛÛ[[‚™Y˜][ÊKZ[^Ø[››İ™XXÚ[ˆ[˜Ü\YÛÛ[[ˆ›İYÚÛÜ™HÜˆ[ÈÜ\˜][ÛœË[™Ù[Xİ
\Ù\‹™[XZ[
X
HÛÛ[[‹›İ[‚™[]JH™]\›œÈÚ\\^ˆØY[™ÈH›İÈÚÜÙHÚ\\^Ø\È[İ™Y˜Z\Ù\È[˜[YÚÙ[˜ÈHÚ[™ÙYÙX[YÛÛ[[ˆ˜Z\Ù\È[\\™Y›İÑ\œ›Ü˜‚‚ˆÈÈÈËŒÈ\XØ][ÛˆÙXÜ™]È˜][‚˜˜\Ú™^ÜÑPÕT‘RÒUÒÑVT’S‘ÏH‰
Ø]Ù^\š[™ËšœÛÛŠHˆÈœ›ÛHH]›Ü›HÙXÜ™]İÜ™H[ˆ›ÙXİ[Û‚™^ÜÑPÕT‘RÒUÕUSKİ˜\‹ÛX‹Ø\ÜÙXÜ™]Ë˜][šœÛÛ‚œ]Ûˆ[HÙXİ\™ZÚ]˜][[š]œš[ˆ	\È‰Õ’TWÒÑVHˆ]Ûˆ[HÙXİ\™ZÚ]˜][]^[Y[ËÜİš\WÚÙ^HÈ˜[YHÛˆİ[‹™]™\ˆ[ˆ\™İ[Y[œ]Ûˆ[HÙXİ\™ZÚ]˜][\İ˜‚˜]Û‚™œ›ÛHÙXİ\™ZÚ][\ÜÙ^\š[™Â™œ›ÛHÙXİ\™ZÚ]˜][[\Ü˜][˜][H˜][›Ü[ŠÜË™[š\›Û–È”ÑPÕT‘RÒUÕUS—KÙ^\š[™Ë™œ›ÛWÙ[Š
KXİÜHœ^[Y[ËX\HŠBœİš\WÚÙ^HH˜][œØÛÜY
œ^[Y[ËÈŠK™Ù]ÜİŠœ^[Y[ËÜİš\WÚÙ^HŠHÈHÛÛ\Û™[ÙY\ÈÛ›H]ÈİÛˆ™Yš^˜‚˜œÂ˜ÛÛœİÈÙ^\š[™Ë˜][HH™\]Z\™J	ÜÙXİ\™ZÚ]	ÊNÂ˜ÛÛœİ˜][H˜][›Ü[Š›ØÙ\ÜË™[‹”ÑPÕT‘RÒUÕUSÙ^\š[™Ë™œ›ÛQ[Š
KÈXİÜˆ	Ü^[Y[ËX\IÈJNÂ˜ÛÛœİİš\RÙ^HH˜][œØÛÜY
	Ü^[Y[ËÉÊK™Ù]İš[™Ê	Ü^[Y[ËÜİš\WÚÙ^IÊNÂ˜‚•™\œÚ[ÛœÈ\™HÙ\
™]Ù\İLHY˜][
K\İ›ŞX™[[İ™\ÈH™\œÚ[Ûˆ›ÜˆÛÛÙ]Y]ÚİÜÈÚÈYÚ]™\šYHKYY\›İ™\ÂHš[H[™]™\HÙXÜ™]\™H[Xİˆ›İ]HÙ^\ÈÚ]ÙXİ\™ZÚ]˜][›İ]KZÙ^\ØY\ˆY[™ÈH™]Èš[X\HÙ^HÈHÙ^\š[™Ë‚‚ˆÈÈÈËÙXšÛÚÜÂ‚˜]Û‚™œ›ÛHÙXİ\™ZÚ][\ÜÙ^\š[™ËÚYÛ™\‚œÚYÛ™\ˆHÚYÛ™\ŠÙ^\š[™Ë™œ›ÛWÙ[Š
JBšYˆ›İÚYÛ™\‹™\šYJ™\]Y\İ˜›ÙK™\]Y\İšXY\œÖÈ–TÚYÛ˜]\™H—JNˆÈ™\^HÚ[™İÈÌÈHY˜][ˆX›Ü
JBˆÈÈÚYÛˆ[ˆİ]ÛÚ[™È™\]Y\İˆXY\ˆHÚYÛ™\‹œÚYÛŠ›ÙJH[™Ù[™]\ÈTÚYÛ˜]\™B˜‚ˆÈÈÈËH\ÜİÛÜ™Â‚˜]Û‚œİÜ™YH\ÚÜ\ÜİÛÜ™
\ÜİÛÜ™
HÈ\™ÛÛŒšYİÜ™HHİš[™ÂšYˆ™\šYWÜ\ÜİÛÜ™
\ÜİÛÜ™İÜ™Y
N‚ˆYˆ™YY×Ü™Z\Ú
İÜ™Y
NˆİÜ™YH\ÚÜ\ÜİÛÜ™
\ÜİÛÜ™
HÈ\Ü˜YHÚ[[HÛˆÙÚ[‚˜‚“Ûˆ›ÙKšœÈÛ\ˆ[ˆÈ\ÙH›İÈHÛX\ˆ\œ›Üˆ[œİXYÙˆ˜Z[[™È]ZY]Kˆ™]™\ˆÙÈÜˆ™]\›ˆH\ÚÈÛY[Ë‚‚ˆÈÈÈËˆ\‹]\Ù\ˆ˜][
Ù\™\ˆØ[››İ™XY
B‚˜]Û‚˜][™XÛİ™\WÚÙ^HH\Ù\•˜][˜Ü™X]J\Ù\—ÚY\ÜÜ˜\ÙKÚ]Ü™XÛİ™\OUYJHÈÚİÈ™XÛİ™\WÚÙ^HÛ˜ÙB™‹œØ]™J\Ù\—ÚY˜][œİ]JHÈ”ÓÓˆÚ]Ü˜\YÙ^\ÈÛ›BÚÙ[ˆH˜][™[˜Ü\Ú][J››İKLH‹^ŠHÈİÜ™HHÚÙ[‚ˆÈ]\‹ÛˆHÛY[Ú]H\ÜÜ˜\ÙN‚˜][H\Ù\•˜][[›ØÚÊ\Ù\—ÚY‹›ØY
\Ù\—ÚY
K\ÜÜ˜\ÙJB˜‚•H\ÜÜ˜\ÙH]\İ™]™\ˆ™HÙ[ÈHÙ\™\‹ˆH›Ü™Ûİ[ˆ\ÜÜ˜\ÙHÚ]İ]H™XÛİ™\HÙ^HYX[œÈH]H\ÈÛÛ™Kˆ]\ÈH\ÚYÛ‹‚‚ˆÈÈÈËÈÙ^H›İ][Û‚‚YH™]ÈÙ^HYÈHÙ^\š[™È[™XZÙH]š[X\XÙY\HÛÛ™Kˆ[ˆ›ÜˆšY[ÈØ[Ú\\‹œ›İ]JÚÙ[‹İ
X
Ü‚˜ÙXİ\™K›X\š×Ù›Ü—Ü›İ][ÛŠØšŠX›ÜˆÔS[Ú[^H›İÜËYÙYÙYH‘PQQJK[™˜][›İ]KZÙ^\Ø›ÜˆH˜][ˆ™[[İ™HHÛÙ^B›Û›HÚ[ˆ™YY×Ü›İ][Û˜\È˜[ÙH]™\]Ú\™H[™Û]Y][šY\È\™H\˜Ú]™Y
H™]\™YÙ^HØ[ˆ›ÈÛ™Ù\ˆ™\šYH[JK‚‚ˆÈÈˆ[\È›ÜˆHYÙ[‚ŒKˆ
Š“™]™\ˆÜš]H[İ\ˆİÛˆÜ\ÙÜ˜\JŠˆ[™™]™\ˆš[\›İ™HˆHÙXİ\™ZÚ]ÛÛœİXİ[Û‹ˆ\ÙHHTNÈYˆ]Ø[››İÈÛÛY][™ËØ^HÛË‚Œ‹ˆ
Š“™]™\ˆš[ÙËÛÛ[Z]Üˆ\ÜİHÙXÜ™]ÊŠ‹Ù^\Ë˜][˜[Y\ÈÜˆ\ÜİÛÜ™Ë[˜ÛY[™È[ˆ[İ\ˆİÛˆİ[[X\šY\ÈÜˆ\İİ]]‚ˆ\ÜÈÙXÜ™]˜[Y\ÈÛˆİ[ˆÜˆ›İYÚ[š\›Û›Y[˜\šXX›\Ë™]™\ˆ\ÈÛÛ[X[™[[™H\™İ[Y[Ë‚ŒËˆ
Š“™]™\ˆİØ[İÈ[˜[YÚÙ[˜[\\™Y›İÑ\œ›Ü˜Üˆ[\\™Y˜][\œ›Ü˜
Šˆ[™Ø\œHÛˆÚ]HY˜][ˆ^HYX[ˆH]HØ\È[İ™YY]YÜ‚ˆ[˜Ü\Y[™\ˆ[›İ\ˆÙ^Kˆİ\™˜XÙH[KÙÈHY[YšY\ˆ
›İH˜[YJK[™İÜH™\]Y\İ‚ˆ
Š“™]™\ˆİÙ\ˆHØY™]HÙ][™ÈÈXZÙHH\İ\ÜÊŠˆ
™\šYHÙ™‹]Y]™\šYšXØ][ÛˆÙ™‹HÚÜ\ˆÙ^KHÙXZÙ\ˆ\Ú
K‚Kˆ
Š‘È›İ[™[Ù^\ËŠŠˆ\ÙHÙ[™\˜]WÚÙ^J
XÈÙ[šÙ^\š[™ØˆH\ÜÜ˜\ÙH\È™Z™XİY\ÈH›ÛİÙ^HÛˆ\œÜÙK‚‹ˆ
Š”Ù]HÛÛ^[X™\˜][JŠˆ
X›KÛÛ[[‹›İÈY
H[™™]™\ˆÚ[™ÙH]›Üˆ^\İ[™È]HÚ]İ]™KY[˜Ü\[™Ë‚Ëˆ
Š‘È›İ[™^İËY[›ÜHÛÛ[[œÊŠˆÚ]H›[™[™^
›ÛÛX[œËİ]\ÈÛÙ\ÊNÈ\]X[]HXZÜË‚ˆ
Š”Ø^HÚ]™[XZ[œËŠŠˆY\ˆ[İHš[š\Ú\İÚ]\Èİ[[œ›İXİY
Ë\ÚË˜XÚİ\ËÓTËİ\ˆ[™İXYÙ\ÊH\Ú[™ÈØÜËÑSÔ–TSÓ‹SPT›Y‚Kˆ
Š‘È›İÛZ[HÛÛ\X[˜ÙKŠŠˆØ^H\Èİ\ÜÈ[İ\ˆÒKÒTPKÑÑˆÛÜšÈˆ][Üİ™]™\ˆ\ÈXZÙ\È[İHÛÛ\X[‹‚ŒLˆYˆH\Ù\ˆØ[ÈH˜][
œÙ\™\ŠˆÚ]ÙÚ[œÈ[™ÛXÚY\Ë™XÛÛ[Y[™[ˆ\İX›\ÚY›ÙXİ[™Ú\™HÙXİ\™ZÚ]È]ÈÈ›İZ[Û™K‚‚ˆÈÈKˆ™\šYH™Y›Ü™H[İHØ^H™Û™H‚‚˜˜\Ú˜ÙÙXİ\™ZÚ]Ü]Ûˆ	‰ˆ]Ûˆ[H[š]\İ\ØÛİ™\ˆ\È\İÈ]ˆÈ™YYÈÜ[[Ú[^H›ÜˆHÔ“H\İÈ
^HÚÚ\Ú]İ]]
B˜ÙÙXİ\™ZÚ]Û›ÙH	‰ˆ›ÙHK]\İÈ›ÙHÊÂœ]Ûˆ[HÙXİ\™ZÚ]ØØ[ˆ›Ú™XİˆKY˜Z[[ÛˆYÚÈH›Ú™Xİ[İHÚ[™ÙYœ]Ûˆ[HÙXİ\™ZÚ]˜][™\šYHKYY\ÈYˆ[İH\ÙYH˜][˜‚[ÛÈÜš]H]X\İÛ™H\İ[ˆH\Ù\‰ÜÈ›Ú™Xİ]›İ™\ÈH
Š›™YØ]]™JŠˆHÚ\\^[İ™YÈ[›İ\ˆ›İÈ\È™Z™XİYZ[^\Â››İ[ˆH]X˜\ÙKH[\\™YÙX[YÛÛ[[ˆ\È™Y\ÙY‚‚ˆÈÈ‹ˆÚ]\œ›ÜœÈYX[‚‚Ÿ\œ›ÜˆYX[š[™ÈÈŸKK_KK_KK_Ÿ[˜[YÚÙ[˜Ü›Û™ÈÙ^KÜ›Û™ÈÛÛ^Y]YÜˆ[˜Ø]YÚ\\^ÚXÚÈHÛÛ^[™Ù^\š[™ÎÈ™]™\ˆYÛ›Ü™HŸ[šÛ›İÛ’Ù^Q\œ›Ü˜ÚÙ[ˆÜš][ˆ[™\ˆHÙ^HY]\È›İ[ˆHÙ^\š[™È™\İÜ™HH™]\™YÙ^HÜˆš[š\ÚH›İ][ÛˆŸ[\\™Y›İÑ\œ›Ü˜HÙX[YÛÛ[[ˆØ\ÈÚ[™ÙYİ]ÚYHH\™X]\È[ˆ[˜ÚY[ÈÛÛ\\™HÚ]˜XÚİ\Ÿ[\\™Y˜][\œ›Ü˜˜][Y]Y[˜Ø]YZ^Y\ÜˆHÜ›Û™ÈÙ^\š[™ÈİÜÈ™\İÜ™Hœ›ÛH˜XÚİ\ÈÚXÚÈÚÈYÜš]HXØÙ\ÜÈŸ˜][ØÚÙY\œ›Ü˜[›İ\ˆ›ØÙ\ÜÈÛÈHØÚÈ™]NÈHØÚÈÛ\ˆ[ˆˆZ[]\È\È™X]Y\ÈX˜[™Û™YŸÜ›Û™Ô\ÜÜ˜\ÙQ\œ›Ü˜Ü›Û™È\ÜÜ˜\ÙHÈ™XÛİ™\HÙ^HÈ[›İ\ˆ\Ù\‰ÜÈİ]H\ÚÈYØZ[È\™H\È›İ™\Ù]ŸÙXÜ™]›İ›İ[™\œ›Ü˜›ÈİXÚXİ]™HÙXÜ™]Üˆ™\œÚ[ÛˆÚXÚÈH˜[YH[™™\œÚ[ÛˆŸØØ[ˆ^]ÛÙHHš[™[™ÜÈ]ÜˆX›İ™HKY˜Z[[Û˜š^ÜˆX\šÈ™]šY]ÙY[™\ÈÙXİ\™ZÚ]ZYÛ›Ü™Nˆ[KZY‚ˆÈÈËˆš[\Â‚‹H‘PQQK›Yİ™\šY]È[™THİ\ˆ0­ÈÔPË›YÚ\™H›Ü›X]È
›Ü›X]]™JH0­ÈØÜËÑSÔ–TSÓ‹SPT›YØ]™\HXÙHÈ[˜Ü\0­ÂˆØÜËÔ•S“ÓÒË›YÜ\˜][™È]0­È™XİÜœËİ™XİÜœËšœÛÛ˜Ü›ÜÜË[[™İXYÙH\İ™XİÜœÈ0­È]Û‹Ù^[\\ËÛÜ›WÜ]ZXÚÜİ\œX[›˜X›H[[Ë‚