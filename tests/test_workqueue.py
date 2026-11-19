from fastapi.testclient import TestClient
from app.main import app
from app import demo


def test_queue_search_saved_filters_and_atomic_bulk():
    with TestClient(app) as c:
        demo.load()
        c.headers['Authorization']='Bearer '+c.post('/api/auth/login',json={'username':'admin','password':'Test-Password-1234'}).json()['token']
        d=c.get('/api/work-queue').json()
        assert d['items'] and all(x['why_attention'] and x['evidence_references'] for x in d['items'])
        f=d['items'][0];fid=f['id']
        assert c.get('/api/search',params={'q':f['asset']}).json()['assets']
        payload={'name':'urgent','filters':{'q':'CVE','owner':'Test owner'}}
        assert c.put('/api/saved-filters',json=payload).status_code==200
        assert c.get('/api/saved-filters').json()['urgent']==payload['filters']
        assert c.post('/api/bulk-triage',json={'finding_ids':[fid,9999999],'workflow':{'owner':'bad'}}).status_code==404
        assert c.get(f'/api/findings/{fid}').json()['workflow'].get('owner')!='bad'
        assert c.post('/api/bulk-triage',json={'finding_ids':[fid],'workflow':{'owner':'Test owner','state':'in_progress'}}).json()['updated']==1
        assert c.get('/api/work-queue?owner=Test%20owner').json()['items'][0]['id']==fid
        assert c.post('/api/bulk-triage',json={'finding_ids':[fid],'workflow':{'state':'accepted_risk'}}).status_code==422
        assert c.delete('/api/saved-filters/urgent').status_code==200
        assert 'urgent' not in c.get('/api/saved-filters').json()
