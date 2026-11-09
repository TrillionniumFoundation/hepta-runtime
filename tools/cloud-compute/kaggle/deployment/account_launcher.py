#!/usr/bin/env python3
"""Explicit, OAuth-only Kaggle account routing for HeptaRuntime subprocesses."""
import argparse,contextlib,datetime as dt,fcntl,io,json,logging,os
from pathlib import Path
import runpy,sys
CONFIG=Path.home()/'.config/hepta-kaggle/accounts.json'
BASE=Path.home()/'.local/share/hepta-kaggle'
RELEASES={'batch':BASE/'releases/batch-0.1.7','session':BASE/'releases/session-0.1.1','interactive':BASE/'releases/interactive-0.1.0'}
SCRIPTS={'batch':'hepta_kaggle.py','session':'hepta_kaggle_session.py','interactive':'hepta_kaggle_interactive.py'}

def isolated_oauth_load(self):
 """Use only the host-selected file, never ambient env/legacy/token fallback."""
 import kaggle_transport as t
 if self._loaded:return
 # Retry safely after a rejected/failed load within this short-lived process.
 if not self.oauth_path.exists():raise t.AdapterError('AUTH_REQUIRED','Authorize this explicit Kaggle account first.')
 fd=os.open(self.oauth_path.parent/'.hepta-credentials.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise t.AdapterError('AUTH_REFRESH_BUSY','This account is refreshing its credential.') from None
  try:data=json.loads(t.private_read(self.oauth_path))
  except (json.JSONDecodeError,UnicodeError):raise t.AdapterError('INVALID_OAUTH_CREDENTIAL','Account OAuth file is invalid.') from None
  if not isinstance(data,dict):raise t.AdapterError('INVALID_OAUTH_CREDENTIAL','Account OAuth file must be an object.')
  if data.get('username')!=self.expected_username:raise t.AdapterError('AUTH_ACCOUNT_MISMATCH','Stored credential account differs from the selected account.')
  refresh,access=data.get('refresh_token'),data.get('access_token')
  if not isinstance(refresh,str) or not refresh:raise t.AdapterError('INVALID_OAUTH_CREDENTIAL','Selected account requires an OAuth refresh credential.')
  t.remember_secret(refresh);t.remember_secret(access)
  try:
   expires=dt.datetime.fromisoformat(data.get('access_token_expiration','').replace('Z','+00:00'))
   if expires.tzinfo is None:expires=expires.replace(tzinfo=dt.timezone.utc)
  except (ValueError,TypeError):expires=dt.datetime.min.replace(tzinfo=dt.timezone.utc)
  if not access or expires<=dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5):
   result=self._request('refresh',{'refresh_token':refresh,'api_version':'API_VERSION_V1','expiration_duration':43200},mutation=True)
   access,seconds=result.get('token'),result.get('expiresIn')
   if isinstance(seconds,str) and seconds.isdigit():seconds=int(seconds)
   if not isinstance(access,str) or not access or type(seconds) not in (int,float) or seconds<=0:raise t.AdapterError('INVALID_REFRESH_RESPONSE','No usable account refresh response.')
   t.remember_secret(access);data['access_token']=access
   data['access_token_expiration']=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=seconds)).isoformat()
   t.atomic_json(self.oauth_path,data)
  if not isinstance(access,str) or any(c.isspace() for c in access):raise t.AdapterError('INVALID_CREDENTIAL','Selected account access credential is invalid.')
  self.token,self.credential_method=access,'oauth';t.remember_secret(access);self._loaded=True
 finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def check_connection(path,entry):
 # The Jupyter protocol cannot introspect Kaggle identity: retain the private,
 # provider-originated notebook binding and refuse cross-account declarations.
 sys.path.insert(0,str(RELEASES['batch']))
 from kaggle_transport import private_read,AdapterError
 try:value=json.loads(private_read(Path(path)))
 except (ValueError,OSError):raise AdapterError('CONNECTION_FILE_INVALID','Cannot read a private account connection file.') from None
 if not isinstance(value,dict) or not str(value.get('notebook_ref','')).startswith(entry['username']+'/'):
  raise AdapterError('AUTH_ACCOUNT_MISMATCH','Jupyter notebook binding belongs to a different account.')

def invocation(alias,mode,args,config):
 entry=config['accounts'][alias]
 forbidden={'--credentials-file','--expected-username','--state-dir'}
 if any(a.split('=',1)[0] in forbidden for a in args):raise ValueError('ACCOUNT_IDENTITY_OVERRIDE_DENIED')
 statekey={'batch':'batch_state_dir','session':'session_state_dir','interactive':'interactive_state_dir'}[mode]
 argv=['--state-dir',entry[statekey]]
 if mode!='interactive':argv+=['--credentials-file',entry['credentials_file'],'--expected-username',entry['username']]
 return entry,[*argv,*args]

def main():
 os.umask(0o077);logging.disable(logging.CRITICAL)
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('account',help='Alias from the private accounts.json configuration');p.add_argument('mode',choices=['batch','session','interactive']);p.add_argument('args',nargs=argparse.REMAINDER)
 a=p.parse_args();config=json.loads(CONFIG.read_text())
 try:entry,argv=invocation(a.account,a.mode,a.args,config)
 except ValueError:
  print(json.dumps({'ok':False,'error':{'code':'ACCOUNT_IDENTITY_OVERRIDE_DENIED'}}));return 2
 for key in ['KAGGLE_API_TOKEN','KAGGLE_USERNAME','KAGGLE_KEY','KAGGLE_CONFIG_DIR']:os.environ.pop(key,None)
 release=RELEASES[a.mode];sys.path.insert(0,str(release))
 if a.mode!='interactive':
  import kaggle_transport
  kaggle_transport.KaggleTransport._load_credentials=isolated_oauth_load
 else:
  for i,arg in enumerate(a.args):
   if arg=='--connection-file' and i+1<len(a.args):check_connection(a.args[i+1],entry)
   elif arg.startswith('--connection-file='):check_connection(arg.split('=',1)[1],entry)
  if a.args==['call']:
   raw=sys.stdin.buffer.read(2*1024*1024+1)
   try:
    value=json.loads(raw);connection=value.get('arguments',{}).get('connection_file')
    if connection:check_connection(connection,entry)
   except (ValueError,AttributeError):pass # adapter returns its own fixed schema error
   sys.stdin=io.TextIOWrapper(io.BytesIO(raw),encoding='utf-8')
 sys.argv=[str(release/SCRIPTS[a.mode]),*argv]
 runpy.run_path(sys.argv[0],run_name='__main__')
 return 0

if __name__=='__main__':
 try:raise SystemExit(main())
 except SystemExit:raise
 except Exception as e:
  # Only reviewed fixed adapter codes may cross the host boundary.
  code=getattr(e,'code','ACCOUNT_LAUNCH_FAILED')
  if not isinstance(code,str) or not code.replace('_','').isalnum():code='ACCOUNT_LAUNCH_FAILED'
  print(json.dumps({'ok':False,'error':{'code':code}}));raise SystemExit(2)
