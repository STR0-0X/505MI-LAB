# XSS in OWASP Juice Shop

**Course:** Cybersecurity Lab
**Academic Year:** 2025/2026
**Student:** Abdelrahman Sharaf
**Target application:** OWASP Juice Shop (Docker image `bkimminich/juice-shop`)

## Lab goal

Identify and exploit two XSS vulnerabilities in OWASP Juice Shop — one DOM-based (the product search) and one Reflected (the order-tracking page) — both using the payload

```
<iframe src="javascript:alert(`xss`)">
```

and explain why they are classified differently even though the visible result (an alert box) looks the same.

## Environment setup

Juice Shop disables potentially dangerous challenges when it detects a containerized environment, so the application was started in **unsafe mode** to enable the XSS challenges:

```
docker run --rm -e NODE_ENV=unsafe -p 3000:3000 bkimminich/juice-shop
```

The application was reached at `http://localhost:3000`. I created an account and logged in (needed later to place an order for the Reflected XSS part).

## DOM-based XSS in the search function

### 1. Normal behaviour of the search

I searched for the word `apple`. The page showed the matching products and the title became `Search Results - apple`. In DevTools → Network there is a `search?q=apple` request, so the term is sent to the server — but only to fetch the products shown in the grid, not to build the title (this becomes important below).

![Fig. 1](https://raw.githubusercontent.com/USERNAME/REPO/main/dom0.png)
*Fig. 1 — Normal search: the title shows "Search Results - apple" and the Network tab shows the `search?q=apple` request.*

### 2. Injecting the script

I replaced `apple` with the payload and pressed Enter:

```
<iframe src="javascript:alert(`xss`)">
```

The application inserted the input into the DOM as HTML without sanitization, so the iframe's `javascript:` URI executed and an alert box appeared with the text `xss`.

![[dom1 .png]]
*Fig. 2 — The "xss" alert box triggered from the Search field.*

Notably, with the payload in the search box the product search returns `No results found` (the payload is not a product), yet the alert still fires. If the injection depended on the server's response, an empty result would produce no script — so the value that lands in the title must be read by client-side JavaScript directly from the URL.

![[dom2.png]]
*Fig. 3 — The alert fires while the results area shows "No results found", showing the injection does not depend on the server response.*

### 3. Why this is DOM XSS

- The value is read directly from the browser (the `q` parameter in the URL) and written back into the page by client-side code.
- The vulnerable flow happens entirely in the browser: the server does not need to echo the value back for the exploit to work — as shown by the alert firing even when the search returned no results.
- The payload never has to be reflected by the server, so the vulnerability is correctly classified as **DOM-based XSS**.

## Reflected XSS in the order-tracking page

### 1. Creating an order

To reach the tracking page I added `Apple Juice (1000ml)` to the basket, opened the basket to confirm it, then went through Checkout (delivery address, delivery method, payment) and placed the order, reaching the order-completion page which provides a `Track Orders` link.

![[reflected0.png]]
*Fig. 4 — Apple Juice (1000ml) added to the basket.*

![[reflected1.png]]
*Fig. 5 — Checkout: delivery address and delivery method selected.*

![[reflected2.png]]
*Fig. 6 — Order-completion page with the Track Orders link and the order id in the URL.*

### 2. Observing the tracking URL and the API

Tracking the order opened a URL of the form `#/track-result?id=<order-id>`, and the title showed `Search Results - <order-id>`. In DevTools → Network the track-order request returned JSON of the form:

```json
{ "status": "success", "data": [ { "orderId": "<order-id>" } ] }
```

The `orderId` field matched the `id` from the URL, i.e. the id is sent to the backend and reflected back in the response.

![[reflected3.png]]
*Fig. 7 — Track-result page: the title shows "Search Results - &lt;order-id&gt;".*

![[reflected4.png]]
*Fig. 8 — Network tab: the track-order response echoes the URL id in the `orderId` field.*

### 3. Changing the id parameter

To confirm the reflection I replaced the real id with a harmless test value, `1234`. The title updated to `Search Results - 1234` and the response's `orderId` changed to `"1234"`. This confirms that whatever is placed in `id` is forwarded to the backend and returned inside `orderId`.

![[reflected5.png]]
*Fig. 9 — id changed to 1234: the response returns `orderId "1234"`, confirming the value is reflected by the server.*

### 4. Injecting the XSS payload

I then replaced `id` with the payload:

```
http://localhost:3000/#/track-result?id=<iframe src="javascript:alert(`xss`)">
```

The backend responded with JSON containing the exact string I sent inside `orderId`. The client-side code inserted this value into the DOM as HTML, which executed the payload and displayed the `xss` alert.

![[reflected6.png]]
*Fig. 10 — Network tab: the server reflects the exact iframe payload back inside the `orderId` field.*

![[reflected7.png]]
*Fig. 11 — The "xss" alert box triggered from the track-result id parameter.*

### 5. Why this is Reflected XSS

- The payload is first sent from the browser to the server as part of the URL (the `id` parameter).
- The server uses this id to build a JSON response and reflects the same value back in the `orderId` field without sanitization.
- The client then reads `orderId` and inserts it into the page as HTML, allowing the script to execute.
- Even though the DOM is involved in the final step, the key point is that the data makes a **round trip to the server and back**, so it is categorized as **Reflected XSS**.

## Comparison: DOM XSS vs Reflected XSS

From the user's perspective both look the same (an alert pops up), but the underlying data flows differ, which justifies the different labels. The difference is the **source of the tainted data and whether the server is part of the vulnerable flow** — not the final sink, which is the same in both cases (an unsafe HTML binding).

| Aspect | DOM XSS — Search | Reflected XSS — Track Order |
|---|---|---|
| Input location | Search bar in the header (`q` parameter of `#/search?q=…`) | `id` parameter of `#/track-result?id=…` |
| How the input is used | Client-side JS reads the value from the URL and writes it into the "Search Results –" title | Client sends the value to the backend track-order endpoint; the server returns it in the JSON `orderId` field; the client then writes `orderId` into the title |
| Server involvement in the vulnerable flow | None. A product-search request is sent, but it is not part of the injection | Yes. The payload is reflected back by the track-order API in the `orderId` field |
| Where HTML injection occurs | Purely client-side DOM update | Client inserts the server-returned `orderId` into the DOM |
| Decisive evidence | The product search returned "No results found", yet the alert still fired (Fig. 3) | Changing id to 1234 changed `orderId` to match (Fig. 9); the payload was returned verbatim in `orderId` (Fig. 10) |

The clearest separation is the evidence: the DOM alert fired even though the server returned `No results found` (the server response was not involved), whereas the Reflected payload appeared in the page only because the server placed it into `orderId`. This also matches the note that Juice Shop's Reflected XSS is not the textbook case: the single-page app returns JSON rather than a rendered HTML page, but the response still contains the attacker's script and the client performs the final DOM insertion.

## Security impact and mitigations

**Impact:** an attacker can craft a URL that executes arbitrary JavaScript in the victim's browser when opened, leading to session theft or malicious redirects.

**Root causes:** insecure use of DOM sinks with untrusted data (an `[innerHTML]` binding with Angular's sanitizer bypassed via `bypassSecurityTrustHtml`), and lack of validation/encoding for the `id` / `orderId` values.

**Recommended mitigations:**

- Do not insert raw user-controlled HTML into the DOM; use safe text/interpolation bindings.
- Avoid Angular pipes that bypass sanitization (such as `bypassSecurityTrustHtml`) on user data.
- Validate and encode any values returned by the backend and later rendered on the client.

## Conclusion

Both challenges were solved with the same `<iframe>` payload, but analysing how the input is processed shows two different classes: the search is DOM-based (the payload is read from the URL and written to the DOM entirely on the client), while order tracking is reflected (the payload is sent to the server, echoed back in `orderId`, and only then inserted into the DOM). The identical visible effect hides two distinct data flows, which is exactly what the "DOM" and "Reflected" labels describe.
