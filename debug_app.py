from app import app
import builtins

# Mock print to capture output if needed, but standard stderr should work
try:
    with app.test_client() as client:
        # Simulate Admin Login
        with client.session_transaction() as sess:
            sess['role'] = 'Admin'
            sess['username'] = 'admin_debug'
        
        print("Testing /admin/dashboard...")
        resp = client.get('/admin/dashboard')
        print(f"Dashboard Status: {resp.status_code}")
        if resp.status_code == 500:
            print("ERROR on Dashboard")

        print("Testing /admin/users...")
        resp = client.get('/admin/users')
        print(f"Users Status: {resp.status_code}")
        if resp.status_code == 500:
            print("ERROR on Users")

        print("Testing /admin/messages...")
        resp = client.get('/admin/messages')
        print(f"Messages Status: {resp.status_code}")
        if resp.status_code == 500:
            print("ERROR on Messages")

except Exception as e:
    print(f"Exception during test: {e}")
