require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "uploads");
const DB_FILE = path.join(DATA_DIR, "db.json");
for (const dir of [DATA_DIR, UPLOAD_DIR]) fs.mkdirSync(dir, { recursive: true });

if (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD || !process.env.ADMIN_EMAIL) {
  console.warn("Set SESSION_SECRET, ADMIN_EMAIL and ADMIN_PASSWORD in your environment before deployment.");
}
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@example.com").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me-now";

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], videos: [], comments: [], likes: [], reports: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  try { const data = JSON.parse(fs.readFileSync(DB_FILE, "utf8")); data.reports ||= []; data.likes ||= []; data.comments ||= []; data.videos ||= []; data.users ||= []; return data; }
  catch { throw new Error("data/db.json is invalid; restore a valid backup."); }
}
let db = loadDb();
function saveDb() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
const id = () => crypto.randomUUID();
const safeUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });
const currentUser = req => req.session.user || null;
const ageVerified = req => !!req.session.ageVerified;
const requireAge = (req,res,next) => ageVerified(req) ? next() : res.status(403).json({error:"Verify that you are 18 or older to continue.", ageVerificationRequired:true});
const requireAuth = (req,res,next) => currentUser(req) ? next() : res.status(401).json({error:"Please log in first."});
const requireAdmin = (req,res,next) => currentUser(req)?.role === "admin" ? next() : res.status(403).json({error:"Admin access required."});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  name: "streamhub.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7*24*60*60*1000 }
}));
app.use(express.static(path.join(ROOT, "public")));
app.post("/api/age-verify", (req,res) => {
  const dob = String(req.body.dob || "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dob)) return res.status(400).json({error:"Enter a valid date of birth."});
  const date = new Date(dob + "T00:00:00Z");
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0,10) !== dob) return res.status(400).json({error:"Enter a valid date of birth."});
  const now = new Date();
  let age = now.getUTCFullYear() - date.getUTCFullYear();
  const beforeBirthday = now.getUTCMonth() < date.getUTCMonth() || (now.getUTCMonth() === date.getUTCMonth() && now.getUTCDate() < date.getUTCDate());
  if (beforeBirthday) age--;
  if (age < 18) return res.status(403).json({error:"You must be 18 or older to access this site."});
  req.session.ageVerified = true;
  req.session.ageVerifiedAt = Date.now();
  res.json({ok:true, ageVerified:true, note:"This is self-declared age confirmation, not legally robust identity verification."});
});
app.get("/media/:filename", requireAge, (req,res) => {
  const filename = path.basename(req.params.filename);
  const video = db.videos.find(v => v.filename === filename && !v.hidden);
  if (!video) return res.status(404).end("Video not found");
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("Cache-Control","private, no-store");
  res.sendFile(path.join(UPLOAD_DIR, filename), err => { if (err && !res.headersSent) res.status(404).end("Media not found"); });
});

const maxMb = Math.max(1, Number(process.env.MAX_UPLOAD_MB || 500));
const storage = multer.diskStorage({
  destination: (_req,_file,cb) => cb(null, UPLOAD_DIR),
  filename: (_req,file,cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase())
});
const upload = multer({
  storage, limits: { fileSize: maxMb * 1024 * 1024 },
  fileFilter: (_req,file,cb) => {
    if (!["video/mp4","video/webm","video/ogg","video/quicktime","video/x-matroska"].includes(file.mimetype)) return cb(new Error("Upload an MP4, WebM, OGG, MOV or MKV video."));
    cb(null,true);
  }
});

app.get("/api/age-status", (req,res) => res.json({ageVerified:ageVerified(req)}));
app.get("/api/me", (req,res) => res.json({ user: currentUser(req) }));
app.post("/api/register", async (req,res) => {
  const name = String(req.body.name || "").trim().slice(0,50);
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8)
    return res.status(400).json({error:"Enter a name, valid email, and password of at least 8 characters."});
  if (email === ADMIN_EMAIL) return res.status(400).json({error:"That email is reserved for the site administrator."});
  if (db.users.some(u => u.email === email)) return res.status(409).json({error:"An account with this email already exists."});
  const user = { id:id(), name, email, passwordHash: await bcrypt.hash(password,12), role:"user", createdAt:new Date().toISOString() };
  db.users.push(user); saveDb();
  req.session.user = safeUser(user);
  res.status(201).json({user:req.session.user});
});
app.post("/api/login", async (req,res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (email === ADMIN_EMAIL && await bcrypt.compare(password, await bcrypt.hash(ADMIN_PASSWORD, 12))) {
    req.session.user = { id:"admin", name:"Administrator", email:ADMIN_EMAIL, role:"admin" };
    return res.json({user:req.session.user});
  }
  const user = db.users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password,user.passwordHash))) return res.status(401).json({error:"Email or password is incorrect."});
  req.session.user = safeUser(user);
  res.json({user:req.session.user});
});
app.post("/api/logout", (req,res) => req.session.destroy(() => res.json({ok:true})));

function publicVideo(v) {
  const owner = db.users.find(u => u.id === v.userId);
  const comments = db.comments.filter(c => c.videoId === v.id);
  return { ...v, url:`/media/${encodeURIComponent(v.filename)}`, uploader: owner?.name || "Administrator",
    likes:db.likes.filter(l=>l.videoId===v.id).length, likedByMe:!!currentUserForPublic?.id, commentsCount:comments.length };
}
let currentUserForPublic = null;
function videoDto(v, req) {
  const owner = db.users.find(u => u.id === v.userId);
  const comments = db.comments.filter(c => c.videoId === v.id);
  return { id:v.id, title:v.title, description:v.description, category:v.category, filename:v.filename,
    url:`/media/${encodeURIComponent(v.filename)}`, uploader:owner?.name || "Administrator",
    createdAt:v.createdAt, views:v.views || 0, likes:db.likes.filter(l=>l.videoId===v.id).length,
    likedByMe:!!currentUser(req) && db.likes.some(l=>l.videoId===v.id && l.userId===currentUser(req).id),
    commentsCount:comments.length };
}
app.get("/api/videos", requireAge, (req,res) => {
  const q = String(req.query.q || "").toLowerCase().trim();
  const videos = db.videos.filter(v => !v.hidden && (!q || `${v.title} ${v.description} ${v.category}`.toLowerCase().includes(q)))
    .sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).map(v=>videoDto(v,req));
  res.json({videos});
});
app.get("/api/videos/:id", requireAge, (req,res) => {
  const v = db.videos.find(x=>x.id===req.params.id && !x.hidden);
  if (!v) return res.status(404).json({error:"Video not found."});
  v.views = (v.views || 0) + 1; saveDb();
  res.json({video:videoDto(v,req), comments:db.comments.filter(c=>c.videoId===v.id).map(c=>({
    id:c.id, text:c.text, createdAt:c.createdAt,
    author: c.userId === "admin" ? "Administrator" : (db.users.find(u=>u.id===c.userId)?.name || "Deleted user")
  }))});
});
app.post("/api/videos", requireAge, requireAuth, upload.single("video"), (req,res) => {
  if (!req.file) return res.status(400).json({error:"Choose a video file."});
  const title = String(req.body.title || "").trim().slice(0,120);
  const description = String(req.body.description || "").trim().slice(0,3000);
  const category = String(req.body.category || "Other").trim().slice(0,40);
  if (req.body.rightsConsent !== "yes" || req.body.adultConsent !== "yes") {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({error:"Confirm that you own/have rights to the video and that every depicted person is an adult who consented to its distribution."});
  }
  if (title.length < 2) { fs.unlinkSync(req.file.path); return res.status(400).json({error:"Video title must be at least 2 characters."}); }
  const video = {id:id(), userId:currentUser(req).id, title, description, category, filename:req.file.filename,
    originalName:req.file.originalname, size:req.file.size, views:0, hidden:false, createdAt:new Date().toISOString()};
  db.videos.push(video); saveDb(); res.status(201).json({video:videoDto(video,req)});
});
app.post("/api/videos/:id/like", requireAge, requireAuth, (req,res) => {
  if (!db.videos.some(v=>v.id===req.params.id && !v.hidden)) return res.status(404).json({error:"Video not found."});
  const i = db.likes.findIndex(l=>l.videoId===req.params.id && l.userId===currentUser(req).id);
  if (i>=0) db.likes.splice(i,1); else db.likes.push({videoId:req.params.id,userId:currentUser(req).id});
  saveDb(); res.json({liked:i<0, likes:db.likes.filter(l=>l.videoId===req.params.id).length});
});
app.post("/api/videos/:id/comments", requireAge, requireAuth, (req,res) => {
  const text = String(req.body.text || "").trim().slice(0,1000);
  if (!text) return res.status(400).json({error:"Comment cannot be empty."});
  if (!db.videos.some(v=>v.id===req.params.id && !v.hidden)) return res.status(404).json({error:"Video not found."});
  const comment = {id:id(),videoId:req.params.id,userId:currentUser(req).id,text,createdAt:new Date().toISOString()};
  db.comments.push(comment); saveDb();
  res.status(201).json({comment:{...comment,author:currentUser(req).name}});
});
app.post("/api/videos/:id/report", requireAge, (req,res) => {
  const video = db.videos.find(v=>v.id===req.params.id && !v.hidden);
  if (!video) return res.status(404).json({error:"Video not found."});
  const reason = String(req.body.reason || "").trim();
  const details = String(req.body.details || "").trim().slice(0,1000);
  const allowed = ["Non-consensual or intimate content","Suspected minor","Copyright infringement","Harassment or exploitation","Illegal content","Other"];
  if (!allowed.includes(reason)) return res.status(400).json({error:"Choose a report reason."});
  db.reports.push({id:id(),videoId:video.id,reason,details,status:"open",createdAt:new Date().toISOString(),reporterId:currentUser(req)?.id || "anonymous"});
  if (reason === "Suspected minor" || reason === "Non-consensual or intimate content") video.hidden = true;
  saveDb(); res.status(201).json({ok:true,message:"Report received. Thank you for helping keep the community safe."});
});
app.get("/api/admin/reports", requireAge, requireAdmin, (_req,res) => res.json({reports:db.reports.map(r=>({
  ...r, videoTitle:db.videos.find(v=>v.id===r.videoId)?.title || "[Video removed]"
})).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))}));
app.patch("/api/admin/reports/:id", requireAge, requireAdmin, (req,res) => {
  const report=db.reports.find(r=>r.id===req.params.id);
  if(!report) return res.status(404).json({error:"Report not found."});
  const status=String(req.body.status||"");
  if(!["open","reviewing","resolved","dismissed"].includes(status)) return res.status(400).json({error:"Invalid report status."});
  report.status=status; report.reviewedAt=new Date().toISOString();
  if(req.body.restoreVideo===true) { const v=db.videos.find(v=>v.id===report.videoId); if(v) v.hidden=false; }
  saveDb(); res.json({ok:true});
});
app.get("/api/admin/stats", requireAge, requireAdmin, (_req,res) => res.json({
  users:db.users.length, videos:db.videos.length, comments:db.comments.length,
  storageBytes:db.videos.reduce((n,v)=>n+(v.size||0),0)
}));
app.get("/api/admin/videos", requireAge, requireAdmin, (req,res) => res.json({videos:db.videos.map(v=>({...videoDto(v,req),hidden:!!v.hidden,originalName:v.originalName,size:v.size}))}));
app.delete("/api/admin/videos/:id", requireAge, requireAdmin, (req,res) => {
  const i=db.videos.findIndex(v=>v.id===req.params.id);
  if(i<0) return res.status(404).json({error:"Video not found."});
  const [v]=db.videos.splice(i,1);
  db.comments=db.comments.filter(c=>c.videoId!==v.id); db.likes=db.likes.filter(l=>l.videoId!==v.id);
  try { fs.unlinkSync(path.join(UPLOAD_DIR,v.filename)); } catch {}
  saveDb(); res.json({ok:true});
});
app.patch("/api/admin/videos/:id", requireAge, requireAdmin, (req,res) => {
  const v=db.videos.find(v=>v.id===req.params.id);
  if(!v) return res.status(404).json({error:"Video not found."});
  v.hidden=!!req.body.hidden; saveDb(); res.json({ok:true,hidden:v.hidden});
});
app.get("/api/admin/users", requireAge, requireAdmin, (_req,res) => res.json({users:db.users.map(u=>({id:u.id,name:u.name,email:u.email,createdAt:u.createdAt}))}));
app.delete("/api/admin/users/:id", requireAge, requireAdmin, (req,res) => {
  db.users=db.users.filter(u=>u.id!==req.params.id);
  db.videos=db.videos.filter(v=>v.userId!==req.params.id);
  const validIds=new Set(db.videos.map(v=>v.id));
  db.comments=db.comments.filter(c=>c.userId!==req.params.id && validIds.has(c.videoId));
  db.likes=db.likes.filter(l=>l.userId!==req.params.id && validIds.has(l.videoId));
  saveDb(); res.json({ok:true});
});
app.use((err,req,res,next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({error:err.code==="LIMIT_FILE_SIZE" ? `Video exceeds ${maxMb} MB upload limit.` : err.message});
  if (err) return res.status(400).json({error:err.message || "Request failed."});
  next();
});
app.listen(PORT,()=>console.log(`StreamHub running at http://localhost:${PORT}`));
