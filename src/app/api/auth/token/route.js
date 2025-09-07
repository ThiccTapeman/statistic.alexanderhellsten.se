// app/api/auth/token/route.ts
import { NextResponse } from "next/server"
import mongoose from "mongoose"
import crypto from "crypto"

const clientSchema = new mongoose.Schema(
    {
        clientId: { type: String, required: true, unique: true },
        clientSecretHash: { type: String, required: true }
    },
    { versionKey: false }
)

const authSchema = new mongoose.Schema(
    {
        token: { type: String, required: true, unique: true, index: true },
        clientId: { type: String, required: true },
        createdAt: { type: Date, default: Date.now, expires: 120 }
    },
    { versionKey: false }
)

const Client = mongoose.models.Client || mongoose.model("Client", clientSchema)
const Auth = mongoose.models.Auth || mongoose.model("Auth", authSchema)

async function connectDB() {
    if (mongoose.connection.readyState === 0)
        await mongoose.connect(process.env.MONGO_URI || "")
}

function hashSecret(secret) {
    return crypto.createHash("sha256").update(secret).digest("hex")
}

function newToken() {
    return crypto.randomUUID()
}

// optional demo seed, idempotent
async function seedDemo() {
    const demoId = "demo-client"
    const demoSecret = process.env.DEMO_CLIENT_SECRET || "demo-secret"
    const exists = await Client.findOne({ clientId: demoId })
    if (!exists)
        await Client.create({ clientId: demoId, clientSecretHash: hashSecret(demoSecret) })
}

export async function POST(req) {
    await connectDB()
    await seedDemo()

    let body
    try {
        body = await req.json()
    } catch {
        return NextResponse.json({ error: "Invalid JSON" }, { status: 400 })
    }

    const { clientId, clientSecret } = body || {}

    if (typeof clientId !== "string" || clientId.length === 0)
        return NextResponse.json({ error: "Invalid clientId" }, { status: 400 })

    if (typeof clientSecret !== "string" || clientSecret.length === 0)
        return NextResponse.json({ error: "Invalid clientSecret" }, { status: 400 })

    const client = await Client.findOne({ clientId })
    if (!client) return NextResponse.json({ error: "Invalid client" }, { status: 401 })

    const providedHash = hashSecret(clientSecret)
    if (providedHash !== client.clientSecretHash)
        return NextResponse.json({ error: "Unauthorized" }, { status: 403 })

    const token = newToken()
    await Auth.create({ token, clientId })

    return NextResponse.json({ success: true, token: token, expires: Date.now() + 120 * 1000 })
}

export async function GET(req) {
    await connectDB()

    const url = new URL(req.url)
    const queryToken = url.searchParams.get("token")
    const authHeader = req.headers.get("authorization")
    const bearer = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null
    const token = queryToken || bearer

    if (!token) return NextResponse.json({ error: "Invalid params" }, { status: 400 })

    const auth = await Auth.findOne({ token })
    if (!auth) return NextResponse.json({ error: "Unauthorized" }, { status: 403 })

    return NextResponse.json({ success: true, clientId: auth.clientId })
}
