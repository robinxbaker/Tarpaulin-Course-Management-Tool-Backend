from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage

import requests
import json
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
# UPDATE REQUIREMENTS ####################################################

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

BUSINESSES = "businesses"
USERS = 'users'
AVATAR = 'avatar'
COURSES = 'courses'
PHOTO_BUCKET = 'm8_photos_baker'
ERROR_NO_BUSINESS = {"Error": "No business with this business_id exists"}
ERROR_400 = {'Error': 'The request body is invalid'}
ERROR_401 = {'Error': 'Unauthorized'}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {'Error': 'Not found'}

# Update the values of the following 3 variables
CLIENT_ID = '1SYO1TviFFw9b3OSfV72YiacsPpVfEei'
CLIENT_SECRET = 'omuQR9CozYgqYUQo0QmSQSQ2Qs9BtVjIUbUuD2YN5Vo-Wsx3RdKS-gP4nP4JFhay'
DOMAIN = 'dev-8jwq6uimi6haletu.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]
CONTENT_NOT_VALID = {'Error': 'The request body is missing at least one of the required attributes'}

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

def jwt_is_user_id(request, user_id):
    decoded_token = verify_jwt(request)

    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)

    sub_in_header = decoded_token['sub']
    if user:
        sub_of_request = user.get('sub')
    else:
        return False

    if sub_in_header != sub_of_request:
        return False
    return True

def content_not_valid(content, list_of_required):
    for value in list_of_required:
        if value not in content:
            return True
    return False

def get_basic_url(current_url):
    basic_url = ""
    slash_count = 0
    for char in str(current_url): # This makes url for me to return
        if char == "/":
            if slash_count < 3:
                slash_count += 1
        if slash_count != 3:
            basic_url += char
    return basic_url

def find_role(entity, role):
    for i, char in enumerate(entity):
        if entity[i: i + 4] == 'role':
            if entity[i + 8: i + 11] == role[0: 3]:
                return True
        break
    return False

def avatar_exists(user_id):
    user_id_str = str(user_id)

    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob with the given file name
    blob = bucket.blob(user_id_str)

    if not blob.exists():
        return False
    return user_id_str

def check_for_error_403(decoded_token, course, id):

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', decoded_token['sub'])  # Add filter for 'role' field
    results_admin_sub = list(query.fetch())
    results_admin_sub = results_admin_sub[0]

    # I have the sub, now I need to get instructor ID with that
    print("\nThis is results_admin_sub: ", results_admin_sub)
    potential_instructor_id = results_admin_sub.key.id

    # Now I have the ID of the instructor from the JWT

    query = client.query(kind=COURSES)
    query.add_filter('instructor_id', '=', potential_instructor_id)  # Add filter for 'role' field
    results_courses = list(query.fetch())
    # Now I have courses with that instructor, I need to check if course ID matches
    is_not_instructor = True

    # I need to query the course

    for course in results_courses:
        if course.key.id == id:
            is_not_instructor = False

    if (results_admin_sub.get('role') != 'admin' and is_not_instructor) or course is None:
        return False
    return True

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
    
# Verify the JWT in the request's Authorization header (does not throw errors, instead returns False)
def verify_jwt_no_error(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return False
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except:
        return False
    if unverified_header["alg"] == "HS256":
        return False
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except:
            return False
        return payload
    else:
        return False


@app.route('/')
def index():
    return "Please navigate to /users to use this API"\

@app.route('/' + USERS, methods=['GET'])
def get_users():
    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401
    
    headers = request.headers
    token = headers['Authorization']
    decoded_token = verify_jwt(request)
    name = payload['name']

    query = client.query(kind=USERS)
    results = list(query.fetch())
    query.add_filter('sub', '=', decoded_token['sub'])  # Add filter for 'role' field
    results_admin_sub = list(query.fetch())
    results_admin_sub = results_admin_sub[0]

    if results_admin_sub.get('role') != 'admin':
        return ERROR_403, 403
 
    for userr in results:
        userr['id'] = userr.key.id
        if 'courses' in userr:
            del userr['courses']
        if 'avatar_url' in userr:
            del userr['avatar_url']

    return (results, 200)


@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # I need to query courses for intructor_id if user is an instructor and students_enrolled if user is a student to add to this 
    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401

    decoded_token = verify_jwt(request)
    
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)

    role = user.get('role')
    sub_in_header = decoded_token['sub']
    sub_of_request = user.get('sub')

    if role != 'admin' and sub_in_header != sub_of_request:
        return ERROR_403, 403
    
    if user is None:
        return ERROR_403, 403
    
    user['id'] = user.key.id

    """query = client.query(kind=USERS)
    results = list(query.fetch())
    query.add_filter('sub', '=', decoded_token['sub'])  # Add filter for 'role' field
    results_admin_sub = list(query.fetch())
    results_admin_sub = results_admin_sub[0]"""

    if role == 'instructor':
        courses = []
        query = client.query(kind=COURSES)
        query.add_filter('instructor_id', '=', user_id)
        results = list(query.fetch())
        for course in results:
            courses.append(get_basic_url(request.url) + '/' + COURSES + '/' + str(course.key.id))
        user['courses'] = courses

    elif role == 'student':
        courses = []
        query = client.query(kind=COURSES)
        # query.add_filter('instructor_id', '=', user_id)
        results = list(query.fetch())
        print("\nThis is results: ", results)
        count = 0
        for course in results:
            print("\nThis is course ", count, " in student: ", course)
        for course in results:
            # print("\nThis is course: ", course)
            for student in course['students_enrolled'].keys():
                if course['students_enrolled'][student] == user_id:
                    courses.append(get_basic_url(request.url) + '/' + COURSES + '/' + str(course.key.id))
        user['courses'] = courses

    print("\nThis is user: ", user)
    if 'avatar_url' in user:
        print("\nThis is user['avatar_url']: ", user['avatar_url'])


    if avatar_exists(user_id):
        user['avatar_url'] = get_basic_url(request.url) + '/' + USERS + '/' + str(user_id) + "/avatar"

    return (user, 200)


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['POST'])
def create_or_update_avatar(user_id):

    user_id_str = str(user_id)

    if 'file' not in request.files:
        return ERROR_400, 400

    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401

    if not jwt_is_user_id(request, user_id):
        return ERROR_403, 403

    file_obj = request.files['file']

    if 'tag' in request.form:
        tag = request.form['tag']
    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file, naming it user_id for ease of checking if exists
    blob = bucket.blob(user_id_str)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj)

    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)

    user['avatar_url'] = get_basic_url(request.url) + '/' + USERS + '/' + user_id_str + "/avatar"
    client.put(user)


    return ({
        "avatar_url": get_basic_url(request.url) + '/' + USERS + '/' + user_id_str + "/avatar"
        }, 200)

@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['GET'])
def get_avatar(user_id):

    user_id_str = str(user_id)

    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401

    if not jwt_is_user_id(request, user_id):
        return ERROR_403, 403

    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob with the given file name
    blob = bucket.blob(user_id_str)

    if not blob:
        return ERROR_404, 404

    # Position the file_obj to its beginning
    file_obj = io.BytesIO()
    try:
        # Download the file from Cloud Storage to the file_obj variable
        blob.download_to_file(file_obj)
        # Position the file_obj to its beginning
        file_obj.seek(0)
        # Send the object as a file in the response with the correct MIME type and file name
        return send_file(file_obj, mimetype='image/x-png', download_name=user_id_str)
    except:
        return ERROR_404, 404
    
@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['DELETE'])
def delete_avatar(user_id):
    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401

    if not jwt_is_user_id(request, user_id):
        return ERROR_403, 403

    try:
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(str(user_id))
        # Delete the file from Cloud Storage
        blob.delete()

        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)

        del user['avatar_url']
        client.put(user)

        return '',204
    except:
        return ERROR_404, 404
    
@app.route('/' + COURSES, methods=['POST'])
def create_course():
    content = request.get_json()
    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401
    
    decoded_token = verify_jwt(request)

    query = client.query(kind=USERS)
    # results = list(query.fetch())

    query.add_filter('sub', '=', decoded_token['sub'])  # Add filter for 'role' field
    results_admin_sub = list(query.fetch())
    results_admin_sub = results_admin_sub[0]
    if results_admin_sub.get('role') != 'admin':
        return ERROR_403, 403
    
    query = client.query(kind=USERS)

    potential_instructor_key = client.key(USERS, content['instructor_id'])
    potential_instructor = client.get(key=potential_instructor_key)
    if potential_instructor['role'] != 'instructor':
        return ERROR_400, 400

    if content_not_valid(content, ['instructor_id', 'number', 'subject', 'term', 'title']):
        return ERROR_400, 400
    

    
    new_course = datastore.entity.Entity(key=client.key(COURSES))
    new_course.update({
        'instructor_id': content['instructor_id'],
        'number': content['number'],
        'subject': content['subject'],
        'term': content['term'],
        'title': content['title'],
        'students_enrolled': {}
    })
    print("\nThis is new_course: ", new_course)
    client.put(new_course)
    new_course['id'] = new_course.key.id
    new_course['self'] = get_basic_url(request.url) + '/' + COURSES + '/' + str(new_course['id'])
    del new_course['students_enrolled']
    return new_course, 201

@app.route('/' + COURSES, methods=['GET'])
def get_courses(offset_amount=0, limit_amount=3):
    offset_amount = int(request.args.get('offset', 0))
    limit_amount = int(request.args.get('limit', 3))

    courses = []
    # I need to retrieve all courses, sort them by title, then return only offset to offset + 2

    query = client.query(kind=COURSES)
    all_courses_as_list = list(query.fetch())
 
    for course in all_courses_as_list:
        courses.append([course['subject'], course])

    print(courses[0][0])
    print(type(courses[0][0]))
    print(type(courses[0][1]))
    print(type(courses[0]))
    print(type(courses))
    
    sorted_courses = sorted(courses, key=lambda x: x[0])
    courses = sorted_courses
    print(courses)

    # Get only ones for that page
    courses = courses[offset_amount: offset_amount + limit_amount]

    for course in courses:
        course[1]['id'] = course[1].key.id
        course[1]['self'] = get_basic_url(request.url) + '/' + COURSES + '/' + str(course[1]['id'])
        if 'students_enrolled' in course[1]:
            del course[1]['students_enrolled']
    coursess = []
    try:
        coursess.append(courses[0][1])
    except:
        pass
    try:
        coursess.append(courses[1][1])
    except:
        pass
    try:
        coursess.append(courses[2][1])
    except:
        pass
    courses = coursess

    return {"courses": courses, "next": get_basic_url(request.url) + "/" + COURSES + "?offset=" + str(offset_amount + limit_amount) + "&limit=" + str(limit_amount)}, 200

@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if course is None:
        return ERROR_404, 404
    course['id'] = course.key.id
    course['self'] = get_basic_url(request.url) + '/' + COURSES + '/' + str(course['id'])
    if 'students_enrolled' in course:
        del course['students_enrolled']
    return course, 200

@app.route('/' + COURSES + '/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    content = request.get_json()
    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401
    
    decoded_token = verify_jwt(request)

    course_key = client.key(COURSES, course_id)
    coursee = client.get(key=course_key)

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', decoded_token['sub'])  # Add filter for 'role' field
    results_admin_sub = list(query.fetch())
    print("\nThis is results_admin_sub: ", results_admin_sub)
    results_admin_sub = results_admin_sub[0]
    if results_admin_sub.get('role') != 'admin' or coursee is None:
        return ERROR_403, 403
    
    if 'instructor_id' in content:
        query = client.query(kind=USERS)
        # results = list(query.fetch())

        query.add_filter('role', '=', 'instructor')  # Add filter for 'role' field
        results_instructor_role = list(query.fetch())
        print('\nThis is results_instructor_role: ', results_instructor_role)
        is_not_instructor = True
        for instructor in results_instructor_role:
            print('\nThis is instructor: ', instructor)
            if instructor.key.id == content['instructor_id']:
                is_not_instructor = False
        if is_not_instructor:
            return ERROR_400, 400
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    # Now we have course
    for key in content.keys():
        course[key] = content[key]
    print("\nThis is course in update: ", course)
    client.put(course)
    course['id'] = course.key.id
    course['self'] = get_basic_url(request.url) + '/' + COURSES + '/' + str(course['id'])
    del course['students_enrolled']
    return course, 200

@app.route('/' + COURSES + '/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401

    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    decoded_token = verify_jwt(request)

    query = client.query(kind=USERS)

    query.add_filter('sub', '=', decoded_token['sub'])  # Add filter for 'role' field
    results_admin_sub = list(query.fetch())
    results_admin_sub = results_admin_sub[0]
    if results_admin_sub.get('role') != 'admin' or course is None:
        return ERROR_403, 403

    client.delete(course_key)
    return '', 204

@app.route('/' + COURSES + '/<int:course_id>/students', methods=['PATCH'])
def update_course_enrollment(course_id):
    content = request.get_json()
    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401
    
    decoded_token = verify_jwt(request)

    print('\nThis is decoded_token: ', decoded_token)

    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    if course is None:
        return ERROR_403, 403

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', decoded_token['sub'])  # Add filter for 'role' field
    results_admin_sub = list(query.fetch())
    results_admin_sub = results_admin_sub[0]



    query = client.query(kind=USERS)
    query.add_filter('role', '=', 'instructor')  # Add filter for 'role' field
    results_instructor_role = list(query.fetch())
    is_not_instructor = True
    for instructor in results_instructor_role:
        print('\nThis is instructor: ', instructor)
        if instructor['sub'] == decoded_token['sub']:
            is_not_instructor = False

    print('\nThis is results_admin_sub.get("role"): ', results_admin_sub.get('role'))
    print('\nThis is is_not_instructor: ', is_not_instructor)
    print('\nThis is course: ', course)

    if (results_admin_sub.get('role') != 'admin' and is_not_instructor) or course is None:
        return ERROR_403, 403
    
    ERROR_409 = {'Error': 'Enrollment data is invalid'}
    
    for add_course in content['add']:
        if add_course in content['remove']:
            return ERROR_409, 409
    
    query = client.query(kind=USERS)
    query.add_filter('role', '=', 'student')  # Add filter for 'role' field
    results_student_role = list(query.fetch())
    is_student = True

    for add_course in content['add']:
        is_student_again = False
        for student in results_student_role:
            if add_course == student.key.id:
                is_student_again = True
        if not is_student_again:
            is_student = False
        course['students_enrolled'][str(add_course)] = add_course
    for remove_course in content['remove']:
        is_student_again = False
        for student in results_student_role:
            if remove_course == student.key.id:
                is_student_again = True
        if not is_student_again:
            is_student = False
        course['students_enrolled'][add_course] = add_course
        if remove_course in course['students_enrolled']:
            del course['student_enrolled'][str(remove_course)]

    if not is_student:
        return ERROR_409, 409
    
    client.put(course)
    
    return '', 200

@app.route('/' + COURSES + '/<int:course_id>/students', methods=['GET'])
def get_course_enrollment(course_id):
    payload = verify_jwt_no_error(request) # I may need to make a new verify_jwt that does not throw errors
    if payload is False:
        return ERROR_401, 401
    
    decoded_token = verify_jwt(request)

    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    
    if not check_for_error_403(decoded_token, course, course_id):
        return ERROR_403, 403

    courses_to_return = []

    for key in course['students_enrolled'].keys():
        courses_to_return.append(course['students_enrolled'][key])

    return courses_to_return, 200

@app.route('/delete_all_courses', methods=['DELETE'])
def delete_all_courses():
    query = client.query(kind=COURSES)
    print("\nThis is query: ", query)
    all_courses_as_list = list(query.fetch())
    print("\nThis is all_courses_as_list: ", all_courses_as_list)
    courses_exist = False

    for course in all_courses_as_list:
        courses_exist = True
        course_key = course.key
        client.delete(course_key)
    if courses_exist:
        return '', 204
    return ERROR_404, 404


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if content_not_valid(content, ['username', 'password']):
        return ERROR_400, 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    r = r.json()
    if 'id_token' in r:
        return jsonify({'token': r['id_token']}), 200, {'Content-Type':'application/json'}
    else:
        return ERROR_401, 401

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)