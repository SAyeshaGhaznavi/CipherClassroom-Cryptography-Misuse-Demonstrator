import { runDemo } from './engine';
import type { AuditEvent, ExperimentInput, ExperimentResult, User } from './types';

const resultKey = 'cipherclassroom-demo-results';
const auditKey = 'cipherclassroom-demo-audit';
const DEMO = import.meta.env.VITE_DEMO_MODE !== 'false';
const BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001/api';
let csrfToken: string | null = null;
type SessionResponse = User & { csrfToken: string; expiresAt: string };
export type PolicyField = 'maxInputLength' | 'criticalKdfIterations' | 'minSafeKdfIterations' | 'maxKdfIterations' | 'minAvalancheBits' | 'maxAvalancheBits' | 'minVigenereKeywordLength';
export type LabPolicy = Record<PolicyField, number>;
const read = <T,>(key: string): T[] => {
  try { const data = JSON.parse(localStorage.getItem(key) || '[]'); return Array.isArray(data)?data:[]; }
  catch { return []; }
};
const save = <T,>(key:string, data:T[]) => localStorage.setItem(key,JSON.stringify(data));
const request = async <T,>(path:string, init:RequestInit = {}):Promise<T> => {
  const method = (init.method || 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set('Content-Type','application/json');
  if (method === 'POST' || method === 'PATCH') {
    if (path !== '/auth/login') {
      if (!csrfToken) throw new Error('Session expired. Please sign in again.');
      headers.set('X-CSRF-Token',csrfToken);
    }
  }
  let response:Response;
  try {
    response = await fetch(`${BASE}${path}`, {...init,credentials:'include',headers});
  } catch {
    throw new Error('Cannot connect to the backend. Check that it is running on localhost:3001.');
  }
  if (!response.ok) {
    const data = await response.json().catch(()=>null);
    throw new Error(data?.message || `Request failed (${response.status}).`);
  }
  return response.json() as Promise<T>;
};
const redact = (type:string) => `Experiment: ${type}; input values omitted`;
export const api = {
  isDemo: DEMO,
  async login(username:string, password:string, role:User['role']='operator'):Promise<User> {
    if (DEMO) return {username:username.trim()||'demo-user',role};
    const session = await request<SessionResponse>('/auth/login',{method:'POST',body:JSON.stringify({username,password})});
    csrfToken = session.csrfToken;
    return {username:session.username,role:session.role};
  },
  async restoreSession():Promise<User|null> {
    if (DEMO) return null;
    try {
      const session = await request<SessionResponse>('/auth/me');
      csrfToken = session.csrfToken;
      return {username:session.username,role:session.role};
    } catch {
      csrfToken = null;
      return null;
    }
  },
  async logout():Promise<void> {
    try {
      if (!DEMO && csrfToken) await request('/auth/logout',{method:'POST'});
    } finally {
      csrfToken = null;
    }
  },
  async exportReport(result:ExperimentResult):Promise<void> {
    if (DEMO) {
      const safe = {id:result.id,type:result.type,title:result.title,timestamp:result.timestamp,status:result.status,severity:result.severity,summary:result.summary,details:result.details.filter(x=>!/(plaintext|ciphertext|digest|pbkdf2|salt|xor)/i.test(x.label)),warnings:result.warnings,evidence:result.evidence,durationMs:result.durationMs,version:result.version,notice:'Sanitized summary only; sensitive experiment values excluded.'};
      const url=URL.createObjectURL(new Blob([JSON.stringify(safe,null,2)],{type:'application/json'}));
      const link=document.createElement('a');link.href=url;link.download=`cipherclassroom-${result.id.slice(0,8)}.json`;link.click();
      setTimeout(()=>URL.revokeObjectURL(url),1000);
      return;
    }
    const report = await request<Record<string,unknown>>(`/reports/${encodeURIComponent(result.id)}/export`);
    const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
    const link=document.createElement('a');link.href=url;link.download=`cipherclassroom-${result.id.slice(0,8)}.json`;link.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  },
  async getPolicy():Promise<LabPolicy> {
    return request<LabPolicy>('/admin/config',{method:'PATCH',body:JSON.stringify({confirm:true})});
  },
  async updatePolicy(field:PolicyField,value:number):Promise<LabPolicy> {
    return request<LabPolicy>('/admin/config',{method:'PATCH',body:JSON.stringify({[field]:value,confirm:true})});
  },
  async run(input:ExperimentInput,user:User):Promise<ExperimentResult> {
    if(!DEMO) return request<ExperimentResult>('/experiments',{method:'POST',body:JSON.stringify(input)});
    if(user.role==='viewer') throw new Error('Viewer accounts cannot run experiments.');
    const result = await runDemo(input);
    const saved = read<ExperimentResult>(resultKey);
    save(resultKey,[result,...saved].slice(0,100));
    await api.log('experiment.run',user,redact(input.type));
    return result;
  },
  async history():Promise<ExperimentResult[]> {return DEMO?read<ExperimentResult>(resultKey):request<ExperimentResult[]>('/experiments');},
  async audits(user:User):Promise<AuditEvent[]> {
    if(user.role!=='admin') throw new Error('Only administrators may view audit events.');
    return DEMO?read<AuditEvent>(auditKey):request<AuditEvent[]>('/admin/audit');
  },
  async log(action:string,user:User,detail:string) {
    if(!DEMO) return;
    const event:AuditEvent = {id:crypto.randomUUID(),timestamp:new Date().toISOString(),action,actor:user.username,detail};
    save(auditKey,[event,...read<AuditEvent>(auditKey)].slice(0,150));
  },
  async clearDemo(user:User) {
    if(!DEMO || user.role!=='admin') throw new Error('Only demo administrators may clear demo data.');
    localStorage.removeItem(resultKey);
    await api.log('demo.reset',user,'Cleared saved demo experiment results');
  }
};
