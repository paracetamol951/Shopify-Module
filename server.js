import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

function verifyShopifySessionToken(req, res, next) {
    const auth = req.header("Authorization") || "";

    if (!auth.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Missing session token" });
    }

    const token = auth.slice("Bearer ".length);

    try {
        const decoded = jwt.verify(token, SHOPIFY_CLIENT_SECRET, {
            algorithms: ["HS256"],
            audience: SHOPIFY_CLIENT_ID
        });

        if (!decoded.dest || !/^https:\/\/[a-z0-9][a-z0-9-]*\.myshopify\.com$/i.test(decoded.dest)) {
            return res.status(401).json({ error: "Invalid shop destination" });
        }

        req.shopifySession = {
            shop: decoded.dest.replace("https://", ""),
            userId: decoded.sub,
            sessionId: decoded.sid
        };

        next();

    } catch (e) {
        return res.status(401).json({
            error: "Invalid session token",
            message: e.message
        });
    }
}
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
app.get("/api/session-check", verifyShopifySessionToken, (req, res) => {
    res.json({
        ok: true,
        shop: req.shopifySession.shop
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
const PHP_GET_TOKEN_URL = process.env.PHP_GET_TOKEN_URL;


function requireProxyKey(req, res, next) {
    if (req.header("X-Proxy-Key") !== PROXY_KEY) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    next();
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
app.get("/api/shop-test", requireProxyKey, async (req, res) => {
    try {
        console.log('shoptest');
        const kashShopId = String(req.query.kash_shop_id || "").trim();
        const tokenData = await getTokenFromPhp(kashShopId);

        const data = await shopifyGraphQL(
            tokenData.shop,
            tokenData.access_token,
            `{ shop { name myshopifyDomain } }`
        );

        res.json({ ok: true, shop: data.shop });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
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