from hia_native_text_publication_fixtures import b64,data,node,file_node,case,EXISTING_LIMIT
def race_cases():
    rows=[]
    def add(name,trigger,action,*,mode=2,setup=None,error=None,published=False,
            actual=None,target=b'target',path=b'/target',after_target=None):
        row=case(name,mode=mode,content=b'new\n',setup=[file_node(b'old\n')] if setup is None else setup,
                 path=path,target=target,error=error,domain='races')
        row['race']={'trigger':trigger,'action':action,'published':published,
                     'actual_data':None if actual is None else data(actual),
                     'after_target_base64':b64(target if after_target is None else after_target)}
        rows.append(row)
    first_stat={'kind':7,'args_prefix':[3,768]}
    stage_close={'kind':3,'args_prefix':[4]}
    rename={'kind':17}
    no_entry='No such file or directory (os error 2)'
    add('grow-during-read',first_stat,{'op':'append','data':data(b'x')},error=15)
    add('shrink-during-read',{'kind':10,'args_prefix':[3]}, {'op':'truncate','size':1},
        setup=[file_node(b'x',size=65537)],error=15)
    add('grow-past-reader-limit',first_stat,{'op':'append','data':data(b'x')},
        setup=[file_node(b'a',size=EXISTING_LIMIT)],error=14)
    add('replace-open-path',{'kind':6},{'op':'replace','data':data(b'rival')},error=5)
    add('unlink-open-path',{'kind':6},{'op':'unlink'},error=5)
    add('replace-after-final-source-stat',{'kind':7,'args_prefix':[3,912]},
        {'op':'replace','data':data(b'rival')},error=22)
    add('unlink-after-final-source-stat',{'kind':7,'args_prefix':[3,912]},
        {'op':'unlink'},error=no_entry)
    add('replace-before-publish',stage_close,{'op':'replace','data':data(b'rival')},error=22)
    add('unlink-before-publish',stage_close,{'op':'unlink'},error=no_entry)
    add('chmod-before-publish',stage_close,{'op':'chmod_and_mtime','mode':0o400},error=22)
    add('competing-create-after-random',{'kind':12},{'op':'create','data':data(b'rival')},
        mode=1,setup=[],error=23)
    add('competing-create-before-probe',{'kind':4},{'op':'create','data':data(b'rival')},
        mode=1,setup=[],error=10)
    add('replace-after-final-source-check',{'kind':5,'args_prefix':[],'arg_equals':{'3':912}},
        {'op':'replace','data':data(b'rival')},published=True,actual=b'new\n')
    add('unlink-after-rename',rename,{'op':'unlink'},error=no_entry,published=True)
    add('same-inode-same-size-overwrite-after-rename',rename,{'op':'overwrite','data':data(b'evil')},
        published=True,actual=b'evil')
    add('shrink-after-rename',rename,{'op':'truncate','size':1},error=25,published=True)
    add('extend-after-rename',rename,{'op':'append','data':data(b'external')},error=25,published=True)
    add('replace-inode-after-rename',rename,{'op':'replace','data':data(b'new\n')},error=25,published=True)
    add('symlink-after-rename',rename,{'op':'symlink','target_base64':b64(b'other')},
        setup=[file_node(b'old\n'),file_node(b'other',path=b'other')],error=25,published=True)
    add('held-parent-directory-renamed',{'kind':4},
        {'op':'rename_parent','from_base64':b64(b'inner'),'to_base64':b64(b'moved')},
        mode=1,setup=[node('directory',b'inner')],target=b'inner/target',path=b'/inner/target',
        after_target=b'moved/target',published=True,actual=b'new\n')
    return rows
