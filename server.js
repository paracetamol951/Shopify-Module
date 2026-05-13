import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

function verifyShopifyWebhookHmac(req) {
    const hmacHeader = req.header("X-Shopify-Hmac-Sha256");

    if (!hmacHeader) return false;

    const digest = crypto
        .createHmac("sha256", SHOPIFY_CLIENT_SECRET)
        .update(req.body)
        .digest("base64");

    return crypto.timingSafeEqual(
        Buffer.from(digest, "utf8"),
        Buffer.from(hmacHeader, "utf8")
    );
}

async function callPhpPrivacyAction(action, payload) {
    const resp = await fetch(process.env.PHP_PRIVACY_WEBHOOK_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Internal-Key": INTERNAL_KEY
        },
        body: JSON.stringify({
            action,
            payload,
            received_at: new Date().toISOString()
        })
    });

    const text = await resp.text();

    if (!resp.ok) {
        throw new Error(`PHP privacy action failed: ${text}`);
    }

    return text ? JSON.parse(text) : {};
}

async function handleCustomerDataRequest(payload) {
    // Demande d’accès aux données client.
    // Tu dois préparer/exporter les données que Kash possède sur ce client.
    return callPhpPrivacyAction("customers_data_request", payload);
}

async function handleCustomerRedact(payload) {
    // Suppression/anonymisation des données client.
    return callPhpPrivacyAction("customers_redact", payload);
}

async function handleShopRedact(payload) {
    // Suppression des données liées à la boutique après désinstallation.
    return callPhpPrivacyAction("shop_redact", payload);
}

const app = express();

app.use(express.static("public"));

app.get("/", (req, res) => {
    res.sendFile("KashModule.html", {
        root: "public"
    });
});

// Webhooks Shopify privacy/GDPR
app.post(
    "/webhooks/shopify/privacy",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        try {
            if (!verifyShopifyWebhookHmac(req)) {
                return res.status(400).send("Invalid HMAC");
            }

            const topic = req.header("X-Shopify-Topic");
            const shop = req.header("X-Shopify-Shop-Domain");
            const payload = JSON.parse(req.body.toString("utf8"));

            console.log("Shopify privacy webhook:", topic, shop, payload);

            switch (topic) {
                case "customers/data_request":
                    await handleCustomerDataRequest(payload);
                    break;

                case "customers/redact":
                    await handleCustomerRedact(payload);
                    break;

                case "shop/redact":
                    await handleShopRedact(payload);
                    break;

                default:
                    return res.status(400).send("Unknown topic");
            }

            return res.status(200).send("OK");
        } catch (e) {
            console.error(e);
            return res.status(500).send("Webhook error");
        }
    }
);
app.post(
    "/webhooks/app/uninstalled",
    express.raw({ type: "application/json" }),
    async (req, res) => {
        try {
            if (!verifyShopifyWebhookHmac(req)) {
                return res.status(400).send("Invalid HMAC");
            }

            const shop = req.header("X-Shopify-Shop-Domain");

            console.log("App uninstalled:", shop);

            await callPhpPrivacyAction("app_uninstalled", {
                shop
            });

            res.status(200).send("OK");

        } catch (e) {
            console.error(e);
            res.status(500).send("Webhook error");
        }
    }
);
app.use(express.json());

const PORT = process.env.PORT || 3000;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL;
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const SCOPES = process.env.SCOPES || "read_products";
const API_VERSION = process.env.API_VERSION || "2026-01";

const PROXY_KEY = process.env.PROXY_KEY;
const INTERNAL_KEY = process.env.INTERNAL_KEY;
const PHP_SAVE_TOKEN_URL = process.env.PHP_SAVE_TOKEN_URL;
const PHP_GET_TOKEN_URL = process.env.PHP_GET_TOKEN_URL;

// Stock temporaire uniquement pour les states OAuth
const oauthStates = new Map();

function isValidShop(shop) {
    return /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i.test(shop);
}

function requireProxyKey(req, res, next) {
    if (req.header("X-Proxy-Key") !== PROXY_KEY) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    next();
}
function verifyOAuthHmac(req) {
    const url = new URL(req.originalUrl, PUBLIC_BASE_URL);
    const params = new URLSearchParams(url.search);

    const hmac = params.get("hmac");

    if (!hmac) return false;

    params.delete("hmac");
    params.delete("signature");

    const message = Array.from(params.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `${key}=${value}`)
        .join("&");

    const digest = crypto
        .createHmac("sha256", SHOPIFY_CLIENT_SECRET)
        .update(message)
        .digest("hex");

    return safeCompareHex(digest, hmac);
}

function safeCompareHex(a, b) {
    const aBuffer = Buffer.from(a, "hex");
    const bBuffer = Buffer.from(b, "hex");

    if (aBuffer.length !== bBuffer.length) return false;

    return crypto.timingSafeEqual(aBuffer, bBuffer);
}
function verifyHmac(query) {
    const params = { ...query };
    const hmac = params.hmac;

    if (!hmac) return false;

    delete params.hmac;
    delete params.signature;

    const message = Object.keys(params)
        .sort()
        .map((key) => `${key}=${params[key]}`)
        .join("&");

    const digest = crypto
        .createHmac("sha256", SHOPIFY_CLIENT_SECRET)
        .update(message)
        .digest("hex");

    return crypto.timingSafeEqual(
        Buffer.from(digest, "utf8"),
        Buffer.from(hmac, "utf8")
    );
}

async function saveTokenInPhp(kashShopId, shop, accessToken, scope) {
    const resp = await fetch(PHP_SAVE_TOKEN_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Internal-Key": INTERNAL_KEY
        },
        body: JSON.stringify({
            kash_shop_id: kashShopId,
            shop,
            access_token: accessToken,
            scope,
            installed_at: new Date().toISOString()
        })
    });

    const text = await resp.text();
    console.log(text);
    if (!resp.ok) {
        throw new Error("PHP save token failed: " + text);
    }

    return JSON.parse(text);
}
async function getTokenFromPhp(kashShopId) {
    const url = PHP_GET_TOKEN_URL + "?kash_shop_id=" + encodeURIComponent(kashShopId);

    const resp = await fetch(url, {
        headers: {
            "X-Internal-Key": INTERNAL_KEY
        }
    });

    const text = await resp.text();

    if (!resp.ok) {
        throw new Error("PHP get token failed: " + text);
    }
    //console.log(text);

    return JSON.parse(text);
}

// Démarrage OAuth
app.get("/auth/start", (req, res) => {
    const shop = String(req.query.shop || "").toLowerCase().trim();
    const kashShopId = String(req.query.kash_shop_id || "").trim();

    if (!isValidShop(shop)) {
        return res.status(400).send("Shop invalide");
    }

    if (!/^[0-9]+$/.test(kashShopId)) {
        return res.status(400).send("kash_shop_id invalide");
    }

    const state = crypto.randomBytes(32).toString("hex");

    oauthStates.set(state, {
        shop,
        kash_shop_id: kashShopId,
        createdAt: Date.now()
    });

    const params = new URLSearchParams({
        client_id: SHOPIFY_CLIENT_ID,
        scope: SCOPES,
        redirect_uri: `${PUBLIC_BASE_URL}/auth/callback`,
        state
    });

    res.redirect(`https://${shop}/admin/oauth/authorize?${params.toString()}`);
});
async function registerPrivacyWebhooks(shop, token) {
    const webhooks = [
        {
            topic: "APP_UNINSTALLED",
            uri: `${PUBLIC_BASE_URL}/webhooks/app/uninstalled`
        }
    ];

    for (const webhook of webhooks) {
        await createWebhook(
            shop,
            token,
            webhook.topic,
            webhook.uri
        );
    }
}
async function createWebhook(shop, token, topic, callbackUrl) {
    const query = `
        mutation webhookSubscriptionCreate(
            $topic: WebhookSubscriptionTopic!,
            $webhookSubscription: WebhookSubscriptionInput!
        ) {
            webhookSubscriptionCreate(
                topic: $topic,
                webhookSubscription: $webhookSubscription
            ) {
                webhookSubscription {
                    id
                    topic
                    endpoint {
                        __typename
                    }
                }
                userErrors {
                    field
                    message
                }
            }
        }
    `;

    const variables = {
        topic,
        webhookSubscription: {
            callbackUrl,
            format: "JSON"
        }
    };

    const data = await shopifyGraphQL(
        shop,
        token,
        query,
        variables
    );

    const result = data.webhookSubscriptionCreate;

    if (result.userErrors.length) {
        throw new Error(JSON.stringify(result.userErrors));
    }

    return result.webhookSubscription;
}
// Callback OAuth
app.get("/auth/callback", async (req, res) => {
    try {
        const shop = String(req.query.shop || "").toLowerCase().trim();
        const code = String(req.query.code || "");
        const state = String(req.query.state || "");

        if (!isValidShop(shop) || !code || !state) {
            return res.status(400).send("Paramètres OAuth invalides");
        }

        /*if (!verifyHmac(req.query)) {
            return res.status(400).send("HMAC invalide");
        }*/
        if (!verifyOAuthHmac(req)) {
            return res.status(400).send("HMAC invalide");
        }

        const savedState = oauthStates.get(state);

        if (!savedState || savedState.shop !== shop) {
            return res.status(400).send("State invalide ou expiré");
        }

        oauthStates.delete(state);

        const tokenResp = await fetch(`https://${shop}/admin/oauth/access_token`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                client_id: SHOPIFY_CLIENT_ID,
                client_secret: SHOPIFY_CLIENT_SECRET,
                code
            })
        });

        const tokenJson = await tokenResp.json();

        if (!tokenResp.ok || !tokenJson.access_token) {
            return res.status(500).send("Erreur récupération token Shopify");
        }

        await saveTokenInPhp(
            savedState.kash_shop_id,
            shop,
            tokenJson.access_token,
            tokenJson.scope
        );
        await registerPrivacyWebhooks(
            shop,
            tokenJson.access_token
        );
        const redirectUrl = new URL(process.env.END_OPERATION_REDIRECT);
        res.redirect(redirectUrl.toString());
        //END_OPERATION_REDIRECT
        /*res.send(`
      <h1>Boutique connectée</h1>
      <p>${shop} est maintenant connectée.</p>
      <p>Le token a été enregistré par ton code PHP.</p>
    `);*/

    } catch (e) {
        console.error(e);
        res.status(500).send(e.message);
    }
});

// Endpoint appelé par ton logiciel PHP pour récupérer les produits
app.get("/api/products", requireProxyKey, async (req, res) => {
    try {
        const kashShopId = String(req.query.kash_shop_id || "").trim();

        if (!/^[0-9]+$/.test(kashShopId)) {
            return res.status(400).json({ error: "kash_shop_id invalide" });
        }

        const tokenData = await getTokenFromPhp(kashShopId);

        if (!tokenData || !tokenData.access_token || !tokenData.kash_shop_id) {
            return res.status(401).json({
                error: "Boutique non connectée",
                connect_url: `${PUBLIC_BASE_URL}/auth/start`
            });
        }

        const products = await getProducts(
            tokenData.shop,
            tokenData.access_token
        );
        res.json({
            kash_shop_id: kashShopId,
            shop: tokenData.shop,
            count: products.length,
            products
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

async function shopifyGraphQL(shop, token, query, variables = {}) {
    const response = await fetch(
        `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Shopify-Access-Token": token
            },
            body: JSON.stringify({ query, variables })
        }
    );

    const json = await response.json();

    if (!response.ok || json.errors) {
        throw new Error(JSON.stringify(json.errors || json));
    }

    return json.data;
}

async function getProducts(shop, token) {
    const query = `
    query Products($cursor: String) {
      products(first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          node {
            id
            legacyResourceId
            title
            handle
            status
            vendor
            productType
            descriptionHtml
            updatedAt
            featuredImage {
              url
              altText
            }
            images(first: 20) {
              edges {
                node {
                  id
                  url
                  altText
                  width
                  height
                }
              }
            }
            variants(first: 50) {
              edges {
                node {
                  id
                  legacyResourceId
                  title
                  sku
                  barcode
                  price
                  compareAtPrice
                  inventoryQuantity
                }
              }
            }
          }
        }
      }
    }
  `;

    let cursor = null;
    let products = [];

    do {
        const data = await shopifyGraphQL(shop, token, query, { cursor });
        const connection = data.products;

        products = products.concat(
            connection.edges.map((edge) => {
                const p = edge.node;

                return {
                    id: p.legacyResourceId,
                    graphql_id: p.id,
                    title: p.title,
                    handle: p.handle,
                    status: p.status,
                    vendor: p.vendor,
                    product_type: p.productType,
                    description_html: p.descriptionHtml,
                    updated_at: p.updatedAt,
                    image: p.featuredImage ? {
                        src: p.featuredImage.url,
                        alt: p.featuredImage.altText
                    } : null,
                    images: p.images.edges.map((i) => ({
                        id: i.node.id,
                        src: i.node.url,
                        alt: i.node.altText,
                        width: i.node.width,
                        height: i.node.height
                    })),
                    variants: p.variants.edges.map((v) => ({
                        id: v.node.legacyResourceId,
                        graphql_id: v.node.id,
                        title: v.node.title,
                        sku: v.node.sku,
                        barcode: v.node.barcode,
                        price: v.node.price,
                        compare_at_price: v.node.compareAtPrice,
                        stock: v.node.inventoryQuantity
                    }))
                };
            })
        );

        cursor = connection.pageInfo.hasNextPage
            ? connection.pageInfo.endCursor
            : null;

    } while (cursor);

    return products;
}

async function getCustomers(shop, token) {
    const query = `
    query Customers($cursor: String) {
      customers(first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          node {
            id
            legacyResourceId
            firstName
            lastName
            displayName
            email
            phone
            numberOfOrders
            amountSpent {
              amount
              currencyCode
            }
            tags
            note
            createdAt
            updatedAt
            defaultAddress {
              id
              firstName
              lastName
              company
              address1
              address2
              city
              province
              provinceCode
              country
              countryCodeV2
              zip
              phone
            }
            addresses {
              id
              firstName
              lastName
              company
              address1
              address2
              city
              province
              provinceCode
              country
              countryCodeV2
              zip
              phone
            }
          }
        }
      }
    }
  `;

    let cursor = null;
    let customers = [];

    do {
        const data = await shopifyGraphQL(shop, token, query, { cursor });
        const connection = data.customers;

        customers = customers.concat(
            connection.edges.map((edge) => {
                const c = edge.node;

                return {
                    id: c.legacyResourceId,
                    graphql_id: c.id,
                    first_name: c.firstName,
                    last_name: c.lastName,
                    display_name: c.displayName,
                    email: c.email,
                    phone: c.phone,
                    orders_count: c.numberOfOrders,
                    total_spent: c.amountSpent ? c.amountSpent.amount : null,
                    currency: c.amountSpent ? c.amountSpent.currencyCode : null,
                    tags: c.tags,
                    note: c.note,
                    created_at: c.createdAt,
                    updated_at: c.updatedAt,
                    default_address: normalizeCustomerAddress(c.defaultAddress),
                    addresses: c.addresses.map(normalizeCustomerAddress)
                };
            })
        );

        cursor = connection.pageInfo.hasNextPage
            ? connection.pageInfo.endCursor
            : null;

    } while (cursor);

    return customers;
}

function normalizeCustomerAddress(a) {
    if (!a) return null;

    return {
        id: a.id,
        first_name: a.firstName,
        last_name: a.lastName,
        company: a.company,
        address1: a.address1,
        address2: a.address2,
        city: a.city,
        province: a.province,
        province_code: a.provinceCode,
        country: a.country,
        country_code: a.countryCodeV2,
        zip: a.zip,
        phone: a.phone
    };
}

app.get("/api/customers", requireProxyKey, async (req, res) => {
    try {
        const kashShopId = String(req.query.kash_shop_id || "").trim();

        if (!/^[0-9]+$/.test(kashShopId)) {
            return res.status(400).json({ error: "kash_shop_id invalide" });
        }

        const tokenData = await getTokenFromPhp(kashShopId);

        if (!tokenData || !tokenData.access_token || !tokenData.shop) {
            return res.status(401).json({
                error: "Boutique non connectée",
                connect_url: `${PUBLIC_BASE_URL}/auth/start`
            });
        }

        const customers = await getCustomers(
            tokenData.shop,
            tokenData.access_token
        );

        res.json({
            kash_shop_id: kashShopId,
            shop: tokenData.shop,
            count: customers.length,
            customers
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});


app.listen(PORT, () => {
    console.log(`Shopify proxy running on port ${PORT}`);
});