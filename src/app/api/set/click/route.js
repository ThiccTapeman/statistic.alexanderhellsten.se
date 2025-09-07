import { NextResponse } from "next/server"
import mongoose from "mongoose"

const clickSchema = new mongoose.Schema(
    {
        clientId: { type: String, required: true, index: true },
        sessionId: { type: String, required: true, index: true },
        x: { type: Number, required: true },
        y: { type: Number, required: true },
        scrollX: { type: Number, required: true },
        scrollY: { type: Number, required: true },
        createdAt: { type: Date, default: Date.now }
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

const Clicks = mongoose.models.Clicks || mongoose.model("Clicks", clickSchema)
const Auth = mongoose.models.Auth || mongoose.model("Auth", authSchema)

async function connectDB() {
    if (mongoose.connection.readyState === 0)
        await mongoose.connect(process.env.MONGO_URI || "")
}

function isFiniteNumber(n) {
    return typeof n === "number" && Number.isFinite(n)
}

export async function POST(req) {
    await connectDB()

    const authHeader = req.headers.get("authorization")
    const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null
    if (!token) return NextResponse.json({ error: "Missing token" }, { status: 401 })

    const auth = await Auth.findOne({ token })
    if (!auth) return NextResponse.json({ error: "Unauthorized" }, { status: 403 })

    let body
    try {
        body = await req.json()
    } catch {
        return NextResponse.json({ error: "Invalid JSON" }, { status: 400 })
    }

    const { x, y, scrollX, scrollY, sessionId, clientId } = body || {}

    if (!isFiniteNumber(x) || !isFiniteNumber(y) || !isFiniteNumber(scrollY) || !isFiniteNumber(scrollX))
        return NextResponse.json({ error: "Invalid coordinates" }, { status: 400 })

    if (typeof sessionId !== "string" || sessionId.length === 0)
        return NextResponse.json({ error: "Invalid sessionId" }, { status: 400 })

    if (typeof clientId !== "string" || clientId.length === 0)
        return NextResponse.json({ error: "Invalid clientId" }, { status: 400 })

    if (clientId !== auth.clientId)
        return NextResponse.json({ error: "Client mismatch" }, { status: 403 })

    await Clicks.create({ x, y, scrollX, scrollY, sessionId, clientId })

    return NextResponse.json({ success: true })
}
