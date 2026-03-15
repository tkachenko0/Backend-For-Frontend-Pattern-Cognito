# Il Browser che sapeva troppo

## Introduzione

Fatta questa premessa, oggi quindi vedremo:

- come perdere 400K transazioni in un paio di click?
- Ma HTTPS ci salva davvero?
- che giochi di indovinello si fanno con gli ataccanti?
- Un framework FE moderno X ci protegge davvero da XSS?
- Perché CORS se ne frega della sicurezza
- Se localstorage non sono sicuri per un token, lo abbiamo sentito tutti tantissime volte, quale e' il posto sicuro?
- Cosa c'entra OAuth2 con tutto questo?
- Cos'è PKCE?
- Ed infine BFF

## Core

### Cross-Site Scripting

- un campo di input non sanitizzato
- un parametro URL
- un commento in un forum
- un messaggio in una chat
- un nome utente o profilo
- un titolo di un post o articolo
- header HTTP manipolati
- notifiche o email
- widget di terze parti
- dipendenze npm con codice malevolo
- estensioni browser maligne
- redirect URL non validati
- qualsiasi cosa che finisce renderizzata nel browser senza essere escapata

Cosa può fare questo script? Tutto quello che può fare JavaScript:

- leggere i cookie
- accedere al localStorage
- fare richieste HTTP
- modificare il DOM
- rubare token di autenticazione
- installare keylogger.

### Cross-Site Request Forgery

CSRF è altrettanto preistorico come XSS, ma un po più subdolo. Non richiede di iniettare codice nel'app. L'attaccante crea una pagina malevola su un altro dominio e sfrutta il fatto che il browser invia automaticamente i cookie con ogni richiesta.

- Account cancellati
- Soldi trasferiti
- dati modificati
- e tanto altro

### Man in the Middle

Può succedere su reti WiFi pubbliche non sicure e vede tutto il traffico HTTP in chiaro.
Non e' cosi difficile da fare come si potrebbe pensare in realta'. E non e' neanche cosi improbabile in realtà.

**Scenari comuni:**

**1. WiFi pubblico non sicuro**: Caffetteria, aeroporto, hotel
**2. DNS Poisoning**: Attaccante modifica DNS, IP dell'attaccante invece del server reale
**3. Router compromesso**: Tutto il traffico passa attraverso l'attaccante

## OAuth

OAuth2 è il protocollo che permette a un'app di accedere alle tue risorse senza mai vedere la tua password.

Pensate a quando fate "Login con Google" su un sito. Non state dando la vostra password di Google a quel sito. State dicendo a Google: "Autorizza questo sito ad accedere al mio profilo." Google vi fa autenticare, vi chiede conferma, e poi dà al sito un token che rappresenta quella autorizzazione.
