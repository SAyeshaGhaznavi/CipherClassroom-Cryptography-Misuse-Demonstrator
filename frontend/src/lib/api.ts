import { runDemo } from './engine';
import type { AuditEvent, ExperimentInput, ExperimentResult, User } from './types';

const resultKey = 'cipherclassroom-demo-results';
const auditKey = 'cipherclassroom-demo-audit';
const DEMO = import.meta.env.VITE_DEMO_MODE !== 'false';
const BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001/api';
const read = <T,>(key: string): T[] => {
  try { const data = JSON.parse(localStorage.getItem(key) || '[]'); return Array.isArray(data)?data:[]; }
  catch { return []; }
};
const save = <T,>(key:string, data:T[]) => localStorage.setItem(key,JSON.stringify(data));
const request = async <T,>(path:string, init?:RequestInit):Promise<T> => {
  const response = await fetch(`${BASE}${path}`,{...init,credentials:'include',headers:{'Content-Type':'application/json',...init?.headers}});
  if (!response.ok) {
    const data = await response.json().catch(()=>null);
    throw new Error(data?.message || `Request failed (${response.status}).`);
  }
  return response.json();
};
const redact = (type:string) => `Experiment: ${type}; input values omitted`;
export const api = {
  isDemo: DEMO,
  async login(username:string, role:User['role']):Promise<User> {
    if(!DEMO) return request<User>('/auth/login',{method:'POST',body:JSON.stringify({username,role})});
    return {username:username.trim()||'demo-user',role};
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
