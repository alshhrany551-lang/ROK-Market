import os, sqlite3, secrets, math, io, struct, re, time
from pathlib import Path
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError

BASE=Path(__file__).resolve().parent
app=Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY',secrets.token_hex(32)),MAX_CONTENT_LENGTH=6*1024*1024,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('HTTPS_ONLY')=='1')
DB=Path(os.environ.get('DATABASE_PATH',BASE/'market.db'))
DB.parent.mkdir(parents=True,exist_ok=True)
UPLOAD=Path(os.environ.get('UPLOAD_DIR',BASE/'static'/'uploads')); UPLOAD.mkdir(parents=True,exist_ok=True)
ADMIN_EMAIL=os.environ.get('ADMIN_EMAIL','').strip().lower()
PRIVATE=Path(os.environ.get('PRIVATE_UPLOAD_DIR',BASE/'private_uploads')); PRIVATE.mkdir(parents=True,exist_ok=True)

def conn():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c

def init_db():
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,admin INTEGER NOT NULL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS listings(id INTEGER PRIMARY KEY,title TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',power TEXT NOT NULL DEFAULT '',vip TEXT NOT NULL DEFAULT '',kingdom TEXT NOT NULL DEFAULT '',price REAL NOT NULL CHECK(price>0),status TEXT NOT NULL DEFAULT 'available' CHECK(status IN ('available','reserved','sold')),created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS images(id INTEGER PRIMARY KEY,listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,filename TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,listing_id INTEGER NOT NULL REFERENCES listings(id),buyer_id INTEGER NOT NULL REFERENCES users(id),kind TEXT NOT NULL CHECK(kind IN ('buy','offer')),amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected','counter','completed','cancelled')),counter_amount REAL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL REFERENCES orders(id),sender_id INTEGER NOT NULL REFERENCES users(id),body TEXT,filename TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS contacts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),body TEXT NOT NULL,reply TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),body TEXT NOT NULL,read INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS login_attempts(email TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0);
  CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_id);
  CREATE INDEX IF NOT EXISTS idx_messages_order ON messages(order_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id,read);''')
init_db()

def q(sql,params=(),one=False):
 with conn() as c:
  r=c.execute(sql,params);return r.fetchone() if one else r.fetchall()

def execute(sql,params=()):
 with conn() as c:return c.execute(sql,params).lastrowid

def current_user():
 return q('SELECT * FROM users WHERE id=?',(session['uid'],),True) if 'uid' in session else None

def login_required(fn):
 @wraps(fn)
 def wrapper(*a,**kw):
  if not current_user():return redirect(url_for('login',next=request.path))
  return fn(*a,**kw)
 return wrapper

def admin_required(fn):
 @wraps(fn)
 @login_required
 def wrapper(*a,**kw):
  if not current_user()['admin']:abort(403)
  return fn(*a,**kw)
 return wrapper

@app.before_request
def csrf_guard():
 if request.method=='POST':
  if not secrets.compare_digest(request.form.get('csrf',''),session.get('csrf','!')):abort(400,'Invalid form token')

@app.context_processor
def context():
 if 'csrf' not in session:session['csrf']=secrets.token_hex(24)
 u=current_user(); unread=q('SELECT COUNT(*) n FROM notifications WHERE user_id=? AND read=0',(u['id'],),True)['n'] if u else 0
 return dict(user=u,csrf=session['csrf'],unread=unread)

def notify(uid,body):execute('INSERT INTO notifications(user_id,body) VALUES(?,?)',(uid,body))
def notify_admins(body):
 for u in q('SELECT id FROM users WHERE admin=1'):notify(u['id'],body)
def image_for(listing_id):
 r=q('SELECT filename FROM images WHERE listing_id=? ORDER BY id LIMIT 1',(listing_id,),True)
 return r['filename'] if r else None
app.jinja_env.globals['image_for']=image_for
def display_price(price):
 return round(float(price)*1.05,2)
app.jinja_env.globals['display_price']=display_price

def valid_image_bytes(data, mimetype):
 """Check file signatures rather than trusting the browser-provided MIME type."""
 if mimetype=='image/jpeg':return data.startswith(b'\xff\xd8\xff') and data.endswith(b'\xff\xd9')
 if mimetype=='image/png':return data.startswith(b'\x89PNG\r\n\x1a\n') and b'IEND' in data[-32:]
 if mimetype=='image/webp':return len(data)>=12 and data[:4]==b'RIFF' and data[8:12]==b'WEBP'
 return False

def upload_image(field,private=False,file=None):
 f=file if file is not None else request.files.get(field)
 if not f or not f.filename:return None
 if f.mimetype not in ('image/jpeg','image/png','image/webp'):abort(400,'Only JPEG, PNG, WEBP images allowed')
 data=f.read(6*1024*1024+1)
 if len(data)>6*1024*1024 or not valid_image_bytes(data,f.mimetype):abort(400,'Invalid image file')
 try:
  img=Image.open(io.BytesIO(data))
  img.verify()
  img=Image.open(io.BytesIO(data))
  if img.width*img.height>24_000_000 or img.width<10 or img.height<10:abort(400,'Invalid image dimensions')
  expected={'image/jpeg':'JPEG','image/png':'PNG','image/webp':'WEBP'}[f.mimetype]
  if img.format!=expected:abort(400,'Image type mismatch')
 except (UnidentifiedImageError,OSError,ValueError,Image.DecompressionBombError):abort(400,'Corrupt image')
 ext={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp'}[f.mimetype]
 name=secrets.token_hex(20)+ext
 (PRIVATE if private else UPLOAD).joinpath(name).write_bytes(data)
 return name

@app.get('/')
def home():return render_template('home.html')
@app.get('/listings')
def listings():
 term=request.args.get('q','').strip()[:100]
 rows=q("SELECT * FROM listings WHERE title LIKE ? OR power LIKE ? OR ('ROK-' || printf('%04d',id)) LIKE ? ORDER BY CASE status WHEN 'available' THEN 0 WHEN 'reserved' THEN 1 ELSE 2 END, id DESC",tuple('%'+term+'%' for _ in range(3)))
 return render_template('listings.html',items=rows,term=term)
@app.get('/listing/<int:lid>')
def listing(lid):
 item=q('SELECT * FROM listings WHERE id=?',(lid,),True)
 if not item:abort(404)
 imgs=q('SELECT * FROM images WHERE listing_id=?',(lid,))
 return render_template('listing.html',item=item,imgs=imgs)

@app.route('/register',methods=['GET','POST'])
def register():
 if request.method=='POST':
  email=request.form.get('email','').strip().lower();pwd=request.form.get('password','')
  if not request.form.get('agree'):flash('You must accept the terms and privacy policy.');return redirect(url_for('register'))
  if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email) or len(email)>254 or len(pwd)<10:flash('Enter a valid email and password of at least 10 characters.');return redirect(url_for('register'))
  try:
   uid=execute('INSERT INTO users(email,password,admin) VALUES(?,?,?)',(email,generate_password_hash(pwd),0))
  except sqlite3.IntegrityError:flash('Email already registered.');return redirect(url_for('register'))
  session.clear();session['uid']=uid;return redirect(url_for('listings'))
 return render_template('auth.html',register=True)
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  email=request.form.get('email','').strip().lower()
  attempt=q('SELECT attempts,locked_until FROM login_attempts WHERE email=?',(email,),True)
  now=int(time.time())
  if attempt and attempt['locked_until']>now:flash('Too many attempts. Try again in 15 minutes.');return redirect(url_for('login'))
  u=q('SELECT * FROM users WHERE email=?',(email,),True)
  if not u or not check_password_hash(u['password'],request.form.get('password','')):
   attempts=(attempt['attempts'] if attempt and attempt['locked_until']>now-900 else 0)+1
   execute('INSERT INTO login_attempts(email,attempts,locked_until) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET attempts=excluded.attempts,locked_until=excluded.locked_until',(email,attempts,now+900 if attempts>=5 else now))
   flash('Invalid login.');return redirect(url_for('login'))
  execute('DELETE FROM login_attempts WHERE email=?',(email,))
  session.clear();session['uid']=u['id'];return redirect(url_for('admin' if u['admin'] else 'my_orders'))
 return render_template('auth.html',register=False)
@app.post('/logout')
def logout():session.clear();return redirect(url_for('home'))

@app.post('/listing/<int:lid>/order')
@login_required
def order(lid):
 item=q('SELECT * FROM listings WHERE id=?',(lid,),True)
 if not item or item['status']!='available':abort(400,'Listing unavailable')
 kind=request.form.get('kind')
 if kind not in ('buy','offer'):abort(400)
 try:amount=round(float(request.form.get('amount','') if kind=='offer' else display_price(item['price'])),2)
 except ValueError:abort(400)
 if not math.isfinite(amount) or amount<=0 or amount>10000000:abort(400)
 if kind=='buy':amount=round(item['price']*1.05,2)
 if q("SELECT id FROM orders WHERE listing_id=? AND buyer_id=? AND status IN ('pending','accepted','counter')",(lid,current_user()['id']),True):
  flash('You already have an active request for this listing.');return redirect(url_for('my_orders'))
 oid=execute('INSERT INTO orders(listing_id,buyer_id,kind,amount) VALUES(?,?,?,?)',(lid,current_user()['id'],kind,amount))
 notify_admins(f'New {kind} request ROK-{lid:04d} / #{oid}')
 return redirect(url_for('order_detail',oid=oid))
@app.get('/orders')
@login_required
def my_orders():
 u=current_user(); rows=q('SELECT o.*,l.title,l.id listing_ref FROM orders o JOIN listings l ON l.id=o.listing_id WHERE o.buyer_id=? ORDER BY o.id DESC',(u['id'],))
 return render_template('orders.html',orders=rows,admin_view=False)

def accessible_order(oid):
 o=q('SELECT o.*,l.title,l.id listing_ref,u.email buyer_email FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users u ON u.id=o.buyer_id WHERE o.id=?',(oid,),True)
 if not o:abort(404)
 u=current_user()
 if not u['admin'] and o['buyer_id']!=u['id']:abort(403)
 return o
@app.route('/order/<int:oid>',methods=['GET','POST'])
@login_required
def order_detail(oid):
 o=accessible_order(oid)
 if request.method=='POST':
  body=request.form.get('body','').strip()[:3000];filename=upload_image('photo',private=True)
  if not body and not filename:abort(400)
  execute('INSERT INTO messages(order_id,sender_id,body,filename) VALUES(?,?,?,?)',(oid,current_user()['id'],body,filename))
  if current_user()['admin']:notify(o['buyer_id'],f'New message about request #{oid}')
  else:notify_admins(f'New message in request #{oid}')
  return redirect(url_for('order_detail',oid=oid))
 msgs=q('SELECT m.*,u.email sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.order_id=? ORDER BY m.id',(oid,))
 return render_template('order_detail.html',o=o,msgs=msgs)
@app.post('/order/<int:oid>/cancel')
@login_required
def cancel_order(oid):
 o=accessible_order(oid)
 if current_user()['admin'] or o['status']!='pending':abort(400)
 execute("UPDATE orders SET status='cancelled' WHERE id=? AND status='pending'",(oid,));notify_admins(f'Request #{oid} cancelled')
 return redirect(url_for('my_orders'))
@app.post('/order/<int:oid>/status')
@admin_required
def order_status(oid):
 o=accessible_order(oid);status=request.form.get('status')
 if status not in ('accepted','rejected','counter','completed','cancelled'):abort(400)
 if status=='completed' and o['status']!='accepted':abort(400,'Accept the request before completing it')
 if status in ('accepted','counter') and o['status'] not in ('pending','counter','accepted'):abort(400,'Invalid status transition')
 if o['status'] in ('completed','cancelled','rejected'):abort(400,'Closed requests cannot be modified')
 counter=None
 if status=='counter':
  if o['kind']!='offer':abort(400,'Only offers can receive counteroffers')
  try:counter=float(request.form.get('counter_amount',''))
  except ValueError:abort(400)
  if not math.isfinite(counter) or counter<=0 or counter>10000000:abort(400)
 execute('UPDATE orders SET status=?,counter_amount=? WHERE id=?',(status,counter,oid))
 notify(o['buyer_id'],f'Request #{oid} status updated: {status}')
 return redirect(url_for('order_detail',oid=oid))
@app.route('/contact',methods=['GET','POST'])
@login_required
def contact():
 if request.method=='POST':
  body=request.form.get('body','').strip()[:3000]
  if not body:abort(400)
  execute('INSERT INTO contacts(user_id,body) VALUES(?,?)',(current_user()['id'],body));notify_admins('New contact message')
  flash('Message sent.');return redirect(url_for('contact'))
 rows=q('SELECT * FROM contacts WHERE user_id=? ORDER BY id DESC',(current_user()['id'],))
 return render_template('contact.html',rows=rows)
@app.get('/notifications')
@login_required
def notifications():
 rows=q('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100',(current_user()['id'],))
 execute('UPDATE notifications SET read=1 WHERE user_id=?',(current_user()['id'],))
 return render_template('notifications.html',rows=rows)
@app.get('/admin')
@admin_required
def admin():
 items=q('SELECT * FROM listings ORDER BY id DESC')
 orders=q('SELECT o.*,u.email buyer_email,l.title FROM orders o JOIN users u ON u.id=o.buyer_id JOIN listings l ON l.id=o.listing_id ORDER BY o.id DESC')
 contacts=q('SELECT c.*,u.email FROM contacts c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC')
 return render_template('admin.html',items=items,orders=orders,contacts=contacts)
@app.route('/admin/listing',methods=['GET','POST'])
@admin_required
def add_listing():
 if request.method=='POST':
  title=request.form.get('title','').strip()[:120]
  try:price=float(request.form.get('price',''))
  except ValueError:abort(400)
  if not title or not math.isfinite(price) or price<=0 or price>10000000:abort(400)
  lid=execute('INSERT INTO listings(title,description,power,vip,kingdom,price) VALUES(?,?,?,?,?,?)',(title,request.form.get('description','')[:4000],request.form.get('power','')[:80],request.form.get('vip','')[:30],request.form.get('kingdom','')[:80],price))
  for photo in request.files.getlist('photos')[:8]:
   f=upload_image('photos',file=photo)
   if f:execute('INSERT INTO images(listing_id,filename) VALUES(?,?)',(lid,f))
  return redirect(url_for('admin'))
 return render_template('edit.html',item=None)
@app.route('/admin/listing/<int:lid>',methods=['GET','POST'])
@admin_required
def edit_listing(lid):
 item=q('SELECT * FROM listings WHERE id=?',(lid,),True)
 if not item:abort(404)
 if request.method=='POST':
  try:price=float(request.form.get('price',''))
  except ValueError:abort(400)
  status=request.form.get('status')
  if not request.form.get('title','').strip() or not math.isfinite(price) or price<=0 or price>10000000 or status not in ('available','reserved','sold'):abort(400)
  execute('UPDATE listings SET title=?,description=?,power=?,vip=?,kingdom=?,price=?,status=? WHERE id=?',(request.form.get('title','')[:120],request.form.get('description','')[:4000],request.form.get('power','')[:80],request.form.get('vip','')[:30],request.form.get('kingdom','')[:80],price,status,lid))
  for photo in request.files.getlist('photos')[:8]:
   f=upload_image('photos',file=photo)
   if f:execute('INSERT INTO images(listing_id,filename) VALUES(?,?)',(lid,f))
  return redirect(url_for('admin'))
 return render_template('edit.html',item=item,photos=q('SELECT * FROM images WHERE listing_id=? ORDER BY id',(lid,)))
@app.post('/admin/listing/<int:lid>/image/<int:iid>/delete')
@admin_required
def delete_listing_image(lid,iid):
 image=q('SELECT * FROM images WHERE id=? AND listing_id=?',(iid,lid),True)
 if not image:abort(404)
 execute('DELETE FROM images WHERE id=? AND listing_id=?',(iid,lid))
 try:(UPLOAD/image['filename']).unlink(missing_ok=True)
 except OSError:pass
 return redirect(url_for('edit_listing',lid=lid))

@app.post('/admin/listing/<int:lid>/delete')
@admin_required
def delete_listing(lid):
 if q('SELECT id FROM orders WHERE listing_id=?',(lid,),True):abort(400,'Cannot delete listing with orders; mark sold instead')
 execute('DELETE FROM listings WHERE id=?',(lid,));return redirect(url_for('admin'))
@app.post('/admin/contact/<int:cid>')
@admin_required
def reply_contact(cid):
 c=q('SELECT * FROM contacts WHERE id=?',(cid,),True)
 if not c:abort(404)
 execute('UPDATE contacts SET reply=? WHERE id=?',(request.form.get('reply','')[:3000],cid));notify(c['user_id'],'Reply to your contact message')
 return redirect(url_for('admin'))
@app.get('/terms')
def terms():return render_template('legal.html',kind='terms')
@app.get('/privacy')
def privacy():return render_template('legal.html',kind='privacy')
@app.get('/uploads/<path:name>')
@login_required
def private_upload(name):
 if '/' in name or '..' in name:abort(404)
 # Images attached to private conversations are only accessible to buyer/admin.
 m=q('SELECT o.buyer_id FROM messages m JOIN orders o ON o.id=m.order_id WHERE m.filename=?',(name,),True)
 if not m or (not current_user()['admin'] and m['buyer_id']!=current_user()['id']):abort(403)
 return send_from_directory(PRIVATE,name)
@app.after_request
def security_headers(response):
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
 response.headers['Cache-Control']='no-store' if request.path.startswith(('/order/','/admin','/uploads/','/contact','/notifications','/orders')) else 'private, max-age=0'
 return response

if __name__=='__main__':
 import sys,getpass
 if len(sys.argv)>1 and sys.argv[1]=='create-admin':
  email=input('Admin email: ').strip().lower()
  pwd=getpass.getpass('Admin password (min 12 chars): ')
  if '@' not in email or len(pwd)<12:raise SystemExit('Invalid email or password too short')
  with conn() as c:
   if c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone():raise SystemExit('Email already exists. Use a fresh admin email.')
   c.execute('INSERT INTO users(email,password,admin) VALUES(?,?,1)',(email,generate_password_hash(pwd)))
  print('Admin created.')
 else:app.run(debug=os.environ.get('FLASK_DEBUG')=='1')
