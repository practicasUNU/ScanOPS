/* FILE: frontend/src/components/m4/CancelStyles.css */
:root {
    --primary: #ff4757;
    --secondary: #2f3542;
    --accent: #ffa502;
    --success: #2ed573;
    --bg: #0f172a;
    --card - bg: #1e293b;
    --text: #f8fafc;
    --border: #334155;
}

.cancel - container {
    min - height: 100vh;
    background: var(--bg);
    color: var(--text);
    display: flex;
    align - items: center;
    justify - content: center;
    font - family: 'Inter', sans - serif;
    padding: 2rem;
}

.cancel - card {
    background: var(--card - bg);
    border: 1px solid var(--border);
    border - radius: 1.5rem;
    padding: 3rem;
    width: 100 %;
    max - width: 500px;
    box - shadow: 0 25px 50px - 12px rgba(0, 0, 0, 0.5);
    animation: fadeIn 0.5s ease - out;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

.cancel - header {
    text - align: center;
    margin - bottom: 2rem;
}

.cancel - title {
    font - size: 2rem;
    font - weight: 800;
    margin - bottom: 0.5rem;
    background: linear - gradient(to right, #ff4757, #ffa502);
    -webkit - background - clip: text;
    -webkit - text - fill - color: transparent;
}

.cancel - subtitle {
    color: #94a3b8;
    font - size: 1rem;
}

.attack - details {
    background: rgba(0, 0, 0, 0.2);
    border - radius: 1rem;
    padding: 1.5rem;
    margin - bottom: 2rem;
    border: 1px dashed var(--border);
}

.detail - item {
    display: flex;
    justify - content: space - between;
    margin - bottom: 0.5rem;
    font - size: 0.9rem;
}

.detail - label { color: #64748b; }
.detail - value { font - weight: 600; color: #e2e8f0; }

.form - group {
    margin - bottom: 1.5rem;
}

.form - label {
    display: block;
    margin - bottom: 0.5rem;
    font - size: 0.875rem;
    font - weight: 500;
}

.form - input {
    width: 100 %;
    background: #0f172a;
    border: 1px solid var(--border);
    border - radius: 0.75rem;
    padding: 0.75rem 1rem;
    color: white;
    transition: all 0.2s;
}

.form - input:focus {
    border - color: var(--primary);
    outline: none;
    box - shadow: 0 0 0 3px rgba(255, 71, 87, 0.2);
}

.btn {
    width: 100 %;
    padding: 1rem;
    border - radius: 0.75rem;
    font - weight: 700;
    cursor: pointer;
    transition: all 0.2s;
    border: none;
    margin - top: 1rem;
}

.btn - primary {
    background: var(--primary);
    color: white;
}

.btn - primary:hover {
    background: #ff6b81;
    transform: scale(1.02);
}

.btn - secondary {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text);
}

.btn - secondary:hover {
    background: rgba(255, 255, 255, 0.05);
}

.countdown {
    text - align: center;
    font - size: 3rem;
    font - weight: 900;
    color: var(--accent);
    margin: 1.5rem 0;
    font - variant - numeric: tabular - nums;
}

.success - icon {
    font - size: 4rem;
    color: var(--success);
    text - align: center;
    margin - bottom: 1.5rem;
}

/* FILE: frontend/src/components/m4/CancelAuthPage.jsx */
import React, { useState } from 'react';
import './CancelStyles.css';

export const CancelAuthPage = ({ token, onAuthSuccess }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const resp = await fetch('/api/m4/cancel/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, token })
            });
            const data = await resp.json();
            if (resp.ok) {
                onAuthSuccess(data.session_token);
            } else {
                alert(data.detail);
            }
        } catch (err) {
            alert('Error de conexión');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="cancel-container">
            <div className="cancel-card">
                <div className="cancel-header">
                    <h1 className="cancel-title">Autorización Requerida</h1>
                    <p className="cancel-subtitle">Inicie sesión para cancelar la explotación de M4</p>
                </div>
                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label className="form-label">Email Corporativo</label>
                        <input
                            className="form-input"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                    </div>
                    <div className="form-group">
                        <label className="form-label">Contraseña</label>
                        <input
                            className="form-input"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
                    </div>
                    <button className="btn btn-primary" type="submit" disabled={loading}>
                        {loading ? 'Verificando...' : 'Acceder al Control'}
                    </button>
                </form>
            </div>
        </div>
    );
};

/* FILE: frontend/src/components/m4/CancelConfirmPage.jsx */
import React, { useState, useEffect } from 'react';
import './CancelStyles.css';

export const CancelConfirmPage = ({ token, sessionToken, onConfirmSuccess }) => {
    const [info, setInfo] = useState(null);
    const [totp, setTotp] = useState('');
    const [pin, setPin] = useState('');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        fetch(`/api/m4/cancel/verify/${token}`)
            .then(res => res.json())
            .then(data => setInfo(data));
    }, [token]);

    const handleConfirm = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const resp = await fetch('/api/m4/cancel/confirm', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, totp_code: totp, pin, session_token: sessionToken })
            });
            const data = await resp.json();
            if (data.success) {
                onConfirmSuccess(data);
            } else {
                alert(data.detail);
            }
        } catch (err) {
            alert('Error al confirmar');
        } finally {
            setLoading(false);
        }
    };

    if (!info) return <div className="cancel-container">Cargando...</div>;

    return (
        <div className="cancel-container">
            <div className="cancel-card">
                <div className="cancel-header">
                    <h1 className="cancel-title">Confirmar Cancelación</h1>
                    <p className="cancel-subtitle">Introduzca sus credenciales de seguridad final</p>
                </div>

                <div className="attack-details">
                    <div className="detail-item">
                        <span className="detail-label">CVE:</span>
                        <span className="detail-value">{info.cve}</span>
                    </div>
                    <div className="detail-item">
                        <span className="detail-label">IP Destino:</span>
                        <span className="detail-value">{info.target_ip}</span>
                    </div>
                </div>

                <form onSubmit={handleConfirm}>
                    <div className="form-group">
                        <label className="form-label">Código TOTP (Auth App)</label>
                        <input
                            className="form-input"
                            type="text"
                            maxLength="6"
                            placeholder="000000"
                            value={totp}
                            onChange={(e) => setTotp(e.target.value)}
                            required
                        />
                    </div>
                    <div className="form-group">
                        <label className="form-label">PIN de Seguridad (4 dígitos)</label>
                        <input
                            className="form-input"
                            type="password"
                            maxLength="4"
                            placeholder="****"
                            value={pin}
                            onChange={(e) => setPin(e.target.value)}
                            required
                        />
                    </div>
                    <button className="btn btn-primary" style={{ backgroundColor: '#e74c3c' }} type="submit" disabled={loading}>
                        {loading ? 'Deteniendo M4...' : '🛑 ACTIVAR KILL SWITCH'}
                    </button>
                </form>
            </div>
        </div>
    );
};

/* FILE: frontend/src/components/m4/CancelExpressPage.jsx */
import React, { useState, useEffect } from 'react';
import './CancelStyles.css';

export const CancelExpressPage = ({ token, onConfirmSuccess }) => {
    const [timeLeft, setTimeLeft] = useState(600); // 10 min
    const [info, setInfo] = useState(null);
    const [totp, setTotp] = useState('');
    const [pin, setPin] = useState('');

    useEffect(() => {
        fetch(`/api/m4/cancel/verify/${token}`)
            .then(res => res.json())
            .then(data => setInfo(data));

        const timer = setInterval(() => {
            setTimeLeft(prev => prev > 0 ? prev - 1 : 0);
        }, 1000);
        return () => clearInterval(timer);
    }, [token]);

    const formatTime = (seconds) => {
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${m}:${s < 10 ? '0' : ''}${s}`;
    };

    if (!info) return <div className="cancel-container">Validando Acceso Express...</div>;

    return (
        <div className="cancel-container">
            <div className="cancel-card" style={{ border: '2px solid var(--accent)' }}>
                <div className="cancel-header">
                    <h1 className="cancel-title">Cancelación Express</h1>
                    <p className="cancel-subtitle">Ataque inminente - Última oportunidad</p>
                </div>

                <div className="countdown">{formatTime(timeLeft)}</div>

                <div className="attack-details">
                    <div className="detail-item"><span className="detail-label">IP:</span><span className="detail-value">{info.target_ip}</span></div>
                    <div className="detail-item"><span className="detail-label">CVE:</span><span className="detail-value">{info.cve}</span></div>
                </div>

                <form onSubmit={async (e) => {
                    e.preventDefault();
                    const resp = await fetch('/api/m4/cancel/confirm', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token, totp_code: totp, pin })
                    });
                    const data = await resp.json();
                    if (data.success) onConfirmSuccess(data);
                    else alert(data.detail);
                }}>
                    <input className="form-input" style={{ marginBottom: '1rem' }} type="text" placeholder="TOTP" value={totp} onChange={e => setTotp(e.target.value)} required />
                    <input className="form-input" type="password" placeholder="PIN" value={pin} onChange={e => setPin(e.target.value)} required />
                    <button className="btn btn-primary" type="submit">CANCELAR AHORA</button>
                </form>
            </div>
        </div>
    );
};

/* FILE: frontend/src/components/m4/CancelSuccessPage.jsx */
import React from 'react';
import './CancelStyles.css';

export const CancelSuccessPage = ({ cancelledBy, cancelledAt }) => {
    return (
        <div className="cancel-container">
            <div className="cancel-card" style={{ textAlign: 'center' }}>
                <div className="success-icon">✅</div>
                <h1 className="cancel-title">M4 Detenido</h1>
                <p className="cancel-subtitle">El Kill Switch ha sido activado con éxito.</p>

                <div className="attack-details" style={{ marginTop: '2rem' }}>
                    <div className="detail-item">
                        <span className="detail-label">Detenido por:</span>
                        <span className="detail-value">{cancelledBy || 'Administrador'}</span>
                    </div>
                    <div className="detail-item">
                        <span className="detail-label">Fecha:</span>
                        <span className="detail-value">{cancelledAt || new Date().toLocaleString()}</span>
                    </div>
                </div>

                <button className="btn btn-secondary" onClick={() => window.location.href = '/dashboard'}>
                    Volver al Dashboard
                </button>
                <button className="btn btn-secondary" style={{ marginTop: '0.5rem' }} onClick={() => window.location.href = '/logs/m4'}>
                    Ver Logs de Auditoría
                </button>
            </div>
        </div>
    );
};
