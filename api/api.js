import express, { Router } from "express"
import serverless from "serverless-http"
import { MongoClient, ObjectId } from "mongodb"
import crypto from "crypto"
import cors from "cors"


const api = express()
const router = Router()
const secure = Router()

api.use(cors())
api.use(express.json())

const uri = process.env.MONGO_URI || "mongodb://localhost:27017/mydb"
const mongoClient = new MongoClient(uri)

let dbAuthorized
let colClients
let colTokens

async function initAuthStore() {
    if (!mongoClient.topology || !mongoClient.topology.isConnected()) {
        await mongoClient.connect()
    }
    if (!dbAuthorized) {
        dbAuthorized = mongoClient.db("analytics")
        colClients = dbAuthorized.collection("clients")
        colTokens = dbAuthorized.collection("tokens")
        await colTokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 })
        const existing = await colClients.findOne({ clientId: "demo-client" })
        if (!existing) {
            await colClients.insertOne({
                clientId: "demo-client",
                clientSecret: "demo-secret"
            })
        }
    }
}

// token issuance
router.post("/auth/token", async (req, res) => {
    try {
        await initAuthStore()
        const { clientId, clientSecret } = req.body || {}
        if (!clientId || !clientSecret) {
            return res.status(400).json({ error: "clientId and clientSecret required" })
        }

        const clientDoc = await colClients.findOne({ clientId })
        if (!clientDoc || clientDoc.clientSecret !== clientSecret) {
            return res.status(401).json({ error: "Invalid credentials" })
        }

        const token = crypto.randomBytes(32).toString("hex")
        const ttlSeconds = 300
        const expiresAt = new Date(Date.now() + ttlSeconds * 1000)

        await colTokens.insertOne({
            token,
            clientId,
            expiresAt
        })

        res.json({
            access_token: token,
            token_type: "Bearer",
            expires_in: ttlSeconds
        })
    } catch (err) {
        res.status(500).json({ error: "Server error" })
    }
})

// auth middleware
async function authenticate(req, res, next) {
    try {
        await initAuthStore()
        const header = req.headers.authorization
        if (!header) return res.status(401).json({ error: "Missing Authorization header" })

        const [scheme, token] = header.split(" ")
        if (scheme !== "Bearer" || !token) {
            return res.status(400).json({ error: "Bad Authorization format" })
        }

        const record = await colTokens.findOne({ token })
        if (!record) return res.status(401).json({ error: "Invalid or expired token" })

        // optional sliding expiration to another 5 minutes
        const newExpiry = new Date(Date.now() + 300 * 1000)
        await colTokens.updateOne({ token }, { $set: { expiresAt: newExpiry } })

        req.auth = { clientId: record.clientId }
        next()
    } catch (err) {
        res.status(500).json({ error: "Server error" })
    }
}

secure.use(authenticate)


// app data db
async function getAppDb() {
    if (!mongoClient.topology || !mongoClient.topology.isConnected()) {
        await mongoClient.connect()
    }
    return mongoClient.db("analytics")
}

// visits
secure.get("/get/visits", async (req, res) => {
    const { url } = req.query || {}
    try {
        const db = await getAppDb()
        const data = await db.collection("visits").find({ url }).toArray()
        res.json({ clientId: req.auth.clientId, data })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})
secure.post("/set/visits", async (req, res) => {
    const { url, time, sessionId } = req.body || {}
    if (!url || !time || !sessionId) {
        return res.status(400).json({ error: "Missing required fields" })
    }
    try {
        const db = await getAppDb()
        const result = await db.collection("visits").insertOne({
            url,
            time,
            sessionId,
            clientId: req.auth.clientId
        })
        res.json({ success: true, id: result.insertedId })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})

// scroll
secure.get("/get/scroll", async (req, res) => {
    const { url } = req.query || {}
    try {
        const db = await getAppDb()
        const data = await db.collection("scroll").find({ url }).toArray()
        res.json({ clientId: req.auth.clientId, data })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})
secure.post("/set/scroll", async (req, res) => {
    const { url, x, y, time, sessionId } = req.body || {}
    if (!url || !x || !y || !time || !sessionId) {
        return res.status(400).json({ error: "Missing required fields" })
    }
    try {
        const db = await getAppDb()
        const result = await db.collection("scroll").insertOne({
            url,
            x,
            y,
            time,
            sessionId,
            clientId: req.auth.clientId
        })
        res.json({ success: true, id: result.insertedId })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})

// clicks
secure.get("/get/clicks", async (req, res) => {
    const { url } = req.query || {}
    try {
        const db = await getAppDb()
        const data = await db.collection("clicks").find({ url }).toArray()
        res.json({ clientId: req.auth.clientId, data })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})
secure.post("/set/click", async (req, res) => {
    const { url, x, y, time, sessionId } = req.body || {}
    if (x == null || y == null || !url || !time || !sessionId) {
        return res.status(400).json({ error: "Missing required fields" })
    }
    try {
        const db = await getAppDb()
        const result = await db.collection("clicks").insertOne({
            url,
            x,
            y,
            time,
            sessionId,
            clientId: req.auth.clientId
        })
        res.json({ success: true, id: result.insertedId })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})

// paths
secure.get("/get/paths", async (req, res) => {
    const { url } = req.query || {}
    try {
        const db = await getAppDb()
        const data = await db.collection("paths").find({ url }).toArray()
        res.json({ clientId: req.auth.clientId, data })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})
secure.post("/get/paths", async (req, res) => {
    const { url, sessionId } = req.body || {}
    if (!sessionId) return res.status(400).json({ error: "Missing sessionId" })
    try {
        const db = await getAppDb()
        const data = await db.collection("paths").find({ sessionId, url }).toArray()
        res.json({ clientId: req.auth.clientId, data })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})
secure.post("/set/path", async (req, res) => {
    const { url, prevUrl, time, sessionId } = req.body || {}
    if (!url || !time || !sessionId) {
        return res.status(400).json({ error: "Missing required fields" })
    }
    try {
        const db = await getAppDb()
        const result = await db.collection("paths").insertOne({
            url,
            prevUrl: prevUrl || null,
            time,
            sessionId,
            clientId: req.auth.clientId
        })
        res.json({ success: true, id: result.insertedId })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})
secure.post("/remove/path", async (req, res) => {
    const { id } = req.body || {}
    if (!id) {
        return res.status(400).json({ error: "Missing id" })
    }
    try {
        const db = await getAppDb()
        const result = await db.collection("paths").deleteOne({ _id: new ObjectId(id) })
        res.json({ success: true, deletedCount: result.deletedCount })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})

// get one specified sessions all data
secure.get("/get/:sessionId", async (req, res) => {
    const { sessionId } = req.params
    if (!sessionId) return res.status(400).json({ error: "Missing sessionId" })

    try {
        const db = await getAppDb()

        const [visits, clicks, paths, scroll] = await Promise.all([
            db.collection("visits").find({ sessionId }).toArray(),
            db.collection("clicks").find({ sessionId }).toArray(),
            db.collection("paths").find({ sessionId }).toArray(),
            db.collection("scroll").find({ sessionId }).toArray()
        ])

        res.json({
            sessionId,
            clientId: req.auth.clientId,
            visits,
            clicks,
            paths,
            scroll
        })
    } catch (err) {
        res.status(500).json({ error: err.message })
    }
})


api.use("/", router)
api.use("/api", secure)

export const handler = serverless(api)
