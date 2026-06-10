"""
mobile_server.py  –  HBILLSOFT Mobile Ordering Server
Runs as a background Flask HTTP server so customers can
browse the menu and place orders from their mobile browser.
"""
 
import os
import sys
import json
import uuid
import datetime
import sqlite3
import socket
import threading
from flask_socketio import SocketIO, emit
 
# ── Path helpers (same pattern as main.py) ───────────────────────────────────
_APP_DIR  = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_APP_DIR, '.hbillsoft')
DB_FILE   = os.path.join(_DATA_DIR, 'sales_data.db')
 
def resource_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(_APP_DIR, filename)
 
# ── Detect local LAN IP ───────────────────────────────────────────────────────
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'
 
MOBILE_PORT = 5050
LOCAL_IP    = get_local_ip()
MOBILE_URL  = f'http://{LOCAL_IP}:{MOBILE_PORT}'
 
# ── Pending orders helpers ────────────────────────────────────────────────────
def init_pending_table():
    """Ensure the pending_mobile_orders table exists."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS pending_mobile_orders (
                id          TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                customer    TEXT,
                table_no    TEXT,
                items_json  TEXT NOT NULL,
                note        TEXT
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f'[MobileServer] init_pending_table error: {e}')
 
def save_pending_order(order_id, customer, table_no, items, note=''):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            'INSERT INTO pending_mobile_orders (id, received_at, customer, table_no, items_json, note) VALUES (?,?,?,?,?,?)',
            (order_id, datetime.datetime.now().isoformat(), customer, table_no, json.dumps(items, ensure_ascii=False), note)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f'[MobileServer] save_pending_order error: {e}')
        return False
 
def get_all_pending() -> list:
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT * FROM pending_mobile_orders ORDER BY received_at ASC'
        ).fetchall()
        conn.close()
        result = []
        for r in rows:
            result.append({
                'id':          r['id'],
                'received_at': r['received_at'],
                'customer':    r['customer'] or '',
                'table_no':    r['table_no']  or '',
                'items':       json.loads(r['items_json']),
                'note':        r['note']  or '',
            })
        return result
    except Exception as e:
        print(f'[MobileServer] get_all_pending error: {e}')
        return []
 
def delete_pending(order_id: str) -> bool:
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute('DELETE FROM pending_mobile_orders WHERE id = ?', (order_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f'[MobileServer] delete_pending error: {e}')
        return False
 
def get_menu_and_settings():
    """Read menu, categories and settings directly from SQLite."""
    if not os.path.exists(DB_FILE):
        print(f'[MobileServer] Database not found at: {DB_FILE}')
        return [], [], {}
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
 
        # Exclude image_data here — served separately via /api/menu/image/<id>
        # to keep the menu JSON response small and fast on mobile
        menu_rows = conn.execute(
            'SELECT id, name, price, category, image, '
            '(CASE WHEN image_data IS NOT NULL AND image_data != "" THEN 1 ELSE 0 END) as has_image '
            'FROM menu_items ORDER BY sort_order, id'
        ).fetchall()
        menu = []
        for r in menu_rows:
            menu.append({
                'id':       r['id'],
                'name':     r['name'],
                'price':    r['price'],
                'category': r['category'],
                'image':    r['image'] or '🍽️',
                'hasImage': bool(r['has_image']),
            })
 
        cat_rows = conn.execute(
            'SELECT id, name, icon FROM categories ORDER BY sort_order, rowid'
        ).fetchall()
        categories = [{'id': r['id'], 'name': r['name'], 'icon': r['icon'] or '🍽️'} for r in cat_rows]
 
        settings_row = conn.execute('SELECT data FROM app_settings WHERE id=1').fetchone()
        settings = json.loads(settings_row['data']) if settings_row else {}
 
        conn.close()
        print(f'[MobileServer] Loaded {len(menu)} menu items, {len(categories)} categories')
        return menu, categories, settings
    except Exception as e:
        print(f'[MobileServer] get_menu_and_settings error: {e}')
        return [], [], {}
 
 
def get_item_image(item_id: int) -> str | None:
    """Fetch image_data for a single menu item."""
    try:
        conn = sqlite3.connect(DB_FILE)
        row = conn.execute(
            'SELECT image_data FROM menu_items WHERE id = ?', (item_id,)
        ).fetchone()
        conn.close()
        return row[0] if row and row[0] else None
    except Exception as e:
        print(f'[MobileServer] get_item_image error: {e}')
        return None
 
# ── Flask app ─────────────────────────────────────────────────────────────────
_flask_app = None
 
def create_flask_app():
    try:
        from flask import Flask, jsonify, request, send_from_directory
    except ImportError:
        print('[MobileServer] Flask not installed. Run: pip install flask')
        return None
 
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hbillsoft-secret'
    socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')
 
    @app.after_request
    def add_cors(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
 
    @app.route('/')
    def index():
        mobile_html = resource_path('mobile_order.html')
        return send_from_directory(os.path.dirname(mobile_html),
                                   os.path.basename(mobile_html))
 
    @app.route('/api/menu')
    def api_menu():
        menu, categories, _ = get_menu_and_settings()
        if not menu:
            print('[MobileServer] WARNING: /api/menu returned 0 items — check that menu is saved in the POS app')
        return jsonify({'ok': True, 'menu': menu, 'categories': categories})
 
    @app.route('/api/menu/image/<int:item_id>')
    def api_menu_image(item_id):
        """Serve image_data for a single item (keeps /api/menu payload small)."""
        data = get_item_image(item_id)
        if not data:
            return jsonify({'ok': False}), 404
        return jsonify({'ok': True, 'imageData': data})
 
    @app.route('/api/settings')
    def api_settings():
        _, _, settings = get_menu_and_settings()
        table_count = int(settings.get('tableCount', 10))
        return jsonify({
            'ok':             True,
            'restaurantName': settings.get('restaurantName', 'Restaurant'),
            'currency':       settings.get('currency', '₹'),
            'address':        settings.get('address', ''),
            'tableCount':     table_count,
        })
 
    @app.route('/api/tables')
    def api_tables():
        _, _, settings = get_menu_and_settings()
        table_count = int(settings.get('tableCount', 10))
        return jsonify({'ok': True, 'tableCount': table_count})
 
    @app.route('/api/order', methods=['POST'])
    def api_order():
        try:
            data     = request.get_json(force=True)
            items    = data.get('items', [])
            customer = data.get('customer', '').strip()
            table_no = data.get('table_no', '').strip()
            note     = data.get('note', '').strip()
 
            if not items:
                return jsonify({'ok': False, 'error': 'No items in order'}), 400
 
            order_id = str(uuid.uuid4())[:8].upper()
            ok = save_pending_order(order_id, customer, table_no, items, note)
            if ok:
                # Emit real-time event to all connected POS clients
                socketio.emit('new_order', {
                    'order_id':   order_id,
                    'customer':   customer,
                    'table_no':   table_no,
                    'items':      items,
                    'note':       note,
                    'received_at': datetime.datetime.now().isoformat()
                })
                return jsonify({'ok': True, 'order_id': order_id})
            else:
                return jsonify({'ok': False, 'error': 'Database error'}), 500
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500
 
    @app.route('/api/pending')
    def api_pending():
        orders = get_all_pending()
        return jsonify({'ok': True, 'orders': orders})
 
    @app.route('/api/pending/<order_id>', methods=['DELETE'])
    def api_dismiss(order_id):
        ok = delete_pending(order_id)
        return jsonify({'ok': ok})

    @app.route('/api/confirm/<order_id>', methods=['POST'])
    def api_confirm(order_id):
        """Staff confirmed the order — notify the customer via Socket.IO."""
        try:
            socketio.emit('order_confirmed', {'order_id': order_id})
            return jsonify({'ok': True})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500

    @app.route('/api/sync', methods=['POST'])
    def api_sync():
        """Receive menu, categories and settings from desktop POS and update local DB."""
        try:
            data       = request.get_json(force=True)
            menu       = data.get('menu', [])
            categories = data.get('categories', [])
            settings   = data.get('settings', {})

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            # Sync menu items
            if menu:
                cursor.execute('DELETE FROM menu_items')
                for i, item in enumerate(menu):
                    cursor.execute(
                        '''INSERT OR REPLACE INTO menu_items
                           (id, name, price, category, image, image_data, sort_order)
                           VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (
                            item.get('id'),
                            item.get('name', ''),
                            float(item.get('price', 0)),
                            item.get('category', ''),
                            item.get('image', '🍽️'),
                            item.get('imageData', None),
                            i
                        )
                    )

            # Sync categories
            if categories:
                cursor.execute('DELETE FROM categories')
                for i, cat in enumerate(categories):
                    cursor.execute(
                        '''INSERT OR REPLACE INTO categories (id, name, icon, sort_order)
                           VALUES (?, ?, ?, ?)''',
                        (cat.get('id'), cat.get('name', ''), cat.get('icon', '🍽️'), i)
                    )

            # Sync settings
            if settings:
                settings_json = json.dumps(settings, ensure_ascii=False)
                cursor.execute(
                    '''INSERT OR REPLACE INTO app_settings (id, data) VALUES (1, ?)''',
                    (settings_json,)
                )

            conn.commit()
            conn.close()
            print(f'[MobileServer] Synced {len(menu)} menu items, {len(categories)} categories')
            return jsonify({'ok': True, 'synced': {'menu': len(menu), 'categories': len(categories)}})
        except Exception as e:
            print(f'[MobileServer] /api/sync error: {e}')
            return jsonify({'ok': False, 'error': str(e)}), 500

    return app, socketio
 
 
# ── Public start function ─────────────────────────────────────────────────────
def start_mobile_server():
    """
    Call this from main.py before webview.start().
    Runs Flask in a daemon thread so it dies when the main process exits.
    """
    init_pending_table()
 
    result = create_flask_app()
    if result is None:
        return  # Flask not available — skip silently
    flask_app, socketio = result
 
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)   # suppress Flask request logs in console
 
    def _run():
        socketio.run(flask_app, host='0.0.0.0', port=MOBILE_PORT, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
 
    t = threading.Thread(target=_run, daemon=True, name='MobileOrderServer')
    t.start()
    print(f'[MobileServer] Listening on {MOBILE_URL}')
