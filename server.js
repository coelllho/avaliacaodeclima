
import express from 'express';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'X-User-ID'],
  credentials: true
}));
app.use(express.json());
app.use(express.static(join(__dirname, 'dist')));

// Email configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'wesleypaulinocoelho@gmail.com',
        pass: process.env.EMAIL_PASS // Você precisará configurar isso
    }
});

// Database setup
const db = new sqlite3.Database('database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT,
      status TEXT DEFAULT 'pending',
      created_at TEXT,
      updated_at TEXT
    )`);

        // Surveys table
        db.run(`CREATE TABLE IF NOT EXISTS surveys (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      status TEXT DEFAULT 'draft',
      unique_link TEXT UNIQUE,
      created_at TEXT,
      updated_at TEXT,
      manager_id TEXT
    )`);

        // Responses table
        db.run(`CREATE TABLE IF NOT EXISTS survey_responses (
      id TEXT PRIMARY KEY,
      survey_id TEXT,
      answers TEXT,
      submitted_at TEXT,
      FOREIGN KEY(survey_id) REFERENCES surveys(id)
    )`);

        // Seed data if empty
        db.get("SELECT count(*) as count FROM surveys", (err, row) => {
            if (row && row.count === 0) {
                console.log("Seeding database...");
                const surveyId = "seed-survey-1";
                const now = new Date().toISOString();

                db.run(`INSERT INTO surveys (id, title, description, status, unique_link, created_at, updated_at, manager_id) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [surveyId, "Pesquisa de Clima Organizacional 2024", "Avaliação anual de engajamento.", "active", "link-123", now, now, "user-1"]
                );
            }
        });
    });
}


// API Routes

// Auth Routes

// Register - Sends email to admin
app.post('/api/auth/register', async (req, res) => {
    const { email } = req.body;
    const id = Math.random().toString(36).substring(2, 15);
    const now = new Date().toISOString();

    try {
        // Check if user already exists
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, existingUser) => {
            if (err) return res.status(500).json({ error: err.message });

            if (existingUser) {
                return res.status(400).json({ error: 'Email já cadastrado. Aguarde aprovação do administrador.' });
            }

            // Insert pending user
            db.run(`INSERT INTO users (id, email, password, status, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?)`,
                [id, email, null, 'pending', now, now],
                async function (err) {
                    if (err) return res.status(500).json({ error: err.message });

                    // Try to send email to admin (optional - won't fail if email not configured)
                    try {
                        if (process.env.EMAIL_PASS) {
                            await transporter.sendMail({
                                from: process.env.EMAIL_USER || 'wesleypaulinocoelho@gmail.com',
                                to: 'wesleypaulinocoelho@gmail.com',
                                subject: 'Nova Solicitação de Acesso - Avaliação de Clima',
                                html: `
                                    <h2>Nova Solicitação de Acesso</h2>
                                    <p><strong>Email:</strong> ${email}</p>
                                    <p><strong>Data:</strong> ${new Date().toLocaleString('pt-BR')}</p>
                                    <p>Para aprovar este usuário, defina uma senha provisória e atualize o banco de dados.</p>
                                `
                            });
                            console.log('✅ Email de notificação enviado!');
                        } else {
                            console.log('⚠️  Email não configurado. Usuário criado mas email não foi enviado.');
                        }
                    } catch (emailError) {
                        console.error('⚠️  Erro ao enviar email (não crítico):', emailError.message);
                    }

                    // Always return success, even if email fails
                    res.json({
                        success: true,
                        message: 'Solicitação registrada! O administrador foi notificado e entrará em contato em breve.'
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!user) {
            return res.status(401).json({ error: 'Usuário não encontrado.' });
        }

        if (user.status === 'pending') {
            return res.status(403).json({ error: 'Acesso pendente de aprovação pelo administrador.' });
        }

        if (user.password !== password) {
            return res.status(401).json({ error: 'Senha incorreta.' });
        }

        // If user is a collaborator, get owner info
        if (user.owner_id) {
            db.get('SELECT email FROM users WHERE id = ?', [user.owner_id], (err, owner) => {
                res.json({
                    success: true,
                    user: {
                        id: user.id,
                        email: user.email,
                        role: user.role || 'user',
                        ownerId: user.owner_id,
                        ownerEmail: owner ? owner.email : null
                    }
                });
            });
        } else {
            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role || 'user',
                    ownerId: null,
                    ownerEmail: null
                }
            });
        }
    });
});

// Get pending users (admin only)
app.get('/api/users/pending', (req, res) => {
    const userId = req.headers['x-user-id'];

    if (!userId) {
        return res.status(401).json({ error: 'Usuário não autenticado' });
    }

    // Verify if user is admin
    db.get('SELECT role FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
        }

        // User is admin, return pending users
        db.all("SELECT id, email, status, created_at FROM users WHERE status = 'pending' ORDER BY created_at DESC", [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    });
});

// Approve User - Sets temporary password and sends email
app.post('/api/auth/approve-user', async (req, res) => {
    const { email, temporaryPassword } = req.body;
    const now = new Date().toISOString();

    if (!email || !temporaryPassword) {
        return res.status(400).json({ error: 'Email e senha provisória são obrigatórios.' });
    }

    try {
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) return res.status(500).json({ error: err.message });

            if (!user) {
                return res.status(404).json({ error: 'Usuário não encontrado.' });
            }

            if (user.status !== 'pending') {
                return res.status(400).json({ error: 'Usuário já foi aprovado.' });
            }

            // Update user status, set temporary password, and ensure role is 'user'
            db.run('UPDATE users SET password = ?, status = ?, role = ?, updated_at = ? WHERE email = ?',
                [temporaryPassword, 'active', 'user', now, email],
                async function (err) {
                    if (err) return res.status(500).json({ error: err.message });

                    // Send email with temporary password
                    try {
                        if (process.env.EMAIL_PASS) {
                            await transporter.sendMail({
                                from: process.env.EMAIL_USER || 'wesleypaulinocoelho@gmail.com',
                                to: email,
                                subject: 'Acesso Aprovado - Avaliação de Clima',
                                html: `
                                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                                        <h2 style="color: #4F46E5;">🎉 Seu Acesso foi Aprovado!</h2>
                                        <p>Olá,</p>
                                        <p>Sua solicitação de acesso ao sistema <strong>Avaliação de Clima</strong> foi aprovada!</p>
                                        
                                        <div style="background-color: #F3F4F6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                                            <h3 style="margin-top: 0; color: #1F2937;">Suas Credenciais de Acesso:</h3>
                                            <p><strong>Email:</strong> ${email}</p>
                                            <p><strong>Senha Provisória:</strong> <code style="background-color: #E5E7EB; padding: 4px 8px; border-radius: 4px; font-size: 16px;">${temporaryPassword}</code></p>
                                        </div>

                                        <div style="background-color: #FEF3C7; padding: 15px; border-left: 4px solid #F59E0B; margin: 20px 0;">
                                            <p style="margin: 0;"><strong>⚠️ Importante:</strong> Por segurança, altere sua senha assim que fizer o primeiro login no sistema.</p>
                                        </div>

                                        <p>Para acessar o sistema, clique no botão abaixo:</p>
                                        
                                        <div style="text-align: center; margin: 30px 0;">
                                            <a href="${process.env.APP_URL || 'http://localhost:5173'}" 
                                               style="background-color: #4F46E5; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block;">
                                                Acessar Sistema
                                            </a>
                                        </div>

                                        <hr style="border: none; border-top: 1px solid #E5E7EB; margin: 30px 0;">
                                        
                                        <p style="color: #6B7280; font-size: 14px;">
                                            Se você não solicitou este acesso, por favor ignore este email ou entre em contato com o administrador.
                                        </p>
                                    </div>
                                `
                            });
                            console.log(`✅ Email de aprovação enviado para ${email}`);
                        } else {
                            console.log('⚠️  Email não configurado. Usuário aprovado mas email não foi enviado.');
                        }
                    } catch (emailError) {
                        console.error('⚠️  Erro ao enviar email (não crítico):', emailError.message);
                    }

                    res.json({
                        success: true,
                        message: 'Usuário aprovado com sucesso! Email enviado com senha provisória.'
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Invite Collaborator - Creates user with owner_id and sends email
app.post('/api/auth/invite-collaborator', async (req, res) => {
    const { email, temporaryPassword, ownerId } = req.body;
    const now = new Date().toISOString();

    if (!email || !temporaryPassword || !ownerId) {
        return res.status(400).json({ error: 'Email, senha provisória e ID do dono são obrigatórios.' });
    }

    try {
        // Check if email already exists
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, existingUser) => {
            if (err) return res.status(500).json({ error: err.message });

            if (existingUser) {
                return res.status(400).json({ error: 'Este email já está cadastrado no sistema.' });
            }

            // Get owner info
            db.get('SELECT email FROM users WHERE id = ?', [ownerId], async (err, owner) => {
                if (err) return res.status(500).json({ error: err.message });

                if (!owner) {
                    return res.status(404).json({ error: 'Usuário dono não encontrado.' });
                }

                // Create collaborator user
                const collaboratorId = Math.random().toString(36).substring(2, 15);

                db.run(`INSERT INTO users (id, email, password, status, role, owner_id, created_at, updated_at) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [collaboratorId, email, temporaryPassword, 'active', 'user', ownerId, now, now],
                    async function (err) {
                        if (err) return res.status(500).json({ error: err.message });

                        // Send email with temporary password
                        try {
                            if (process.env.EMAIL_PASS) {
                                await transporter.sendMail({
                                    from: process.env.EMAIL_USER || 'wesleypaulinocoelho@gmail.com',
                                    to: email,
                                    subject: 'Convite para Colaborar - Avaliação de Clima',
                                    html: `
                                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                                            <h2 style="color: #4F46E5;">🤝 Você foi Convidado para Colaborar!</h2>
                                            <p>Olá,</p>
                                            <p><strong>${owner.email}</strong> convidou você para colaborar no sistema <strong>Avaliação de Clima</strong>!</p>
                                            
                                            <div style="background-color: #F3F4F6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                                                <h3 style="margin-top: 0; color: #1F2937;">Suas Credenciais de Acesso:</h3>
                                                <p><strong>Email:</strong> ${email}</p>
                                                <p><strong>Senha Provisória:</strong> <code style="background-color: #E5E7EB; padding: 4px 8px; border-radius: 4px; font-size: 16px;">${temporaryPassword}</code></p>
                                            </div>

                                            <div style="background-color: #DBEAFE; padding: 15px; border-left: 4px solid #3B82F6; margin: 20px 0;">
                                                <p style="margin: 0;"><strong>ℹ️ Como Colaborador:</strong></p>
                                                <ul style="margin: 10px 0;">
                                                    <li>Você terá acesso às pesquisas de ${owner.email}</li>
                                                    <li>Poderá criar e gerenciar pesquisas compartilhadas</li>
                                                    <li>Verá os mesmos dados e relatórios</li>
                                                </ul>
                                            </div>

                                            <div style="background-color: #FEF3C7; padding: 15px; border-left: 4px solid #F59E0B; margin: 20px 0;">
                                                <p style="margin: 0;"><strong>⚠️ Importante:</strong> Por segurança, altere sua senha assim que fizer o primeiro login no sistema.</p>
                                            </div>

                                            <p>Para acessar o sistema, clique no botão abaixo:</p>
                                            
                                            <div style="text-align: center; margin: 30px 0;">
                                                <a href="${process.env.APP_URL || 'http://localhost:5173'}" 
                                                   style="background-color: #4F46E5; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block;">
                                                    Acessar Sistema
                                                </a>
                                            </div>

                                            <hr style="border: none; border-top: 1px solid #E5E7EB; margin: 30px 0;">
                                            
                                            <p style="color: #6B7280; font-size: 14px;">
                                                Se você não esperava este convite, por favor ignore este email ou entre em contato com ${owner.email}.
                                            </p>
                                        </div>
                                    `
                                });
                                console.log(`✅ Email de convite enviado para ${email}`);
                            } else {
                                console.log('⚠️  Email não configurado. Colaborador criado mas email não foi enviado.');
                            }
                        } catch (emailError) {
                            console.error('⚠️  Erro ao enviar email (não crítico):', emailError.message);
                        }

                        res.json({
                            success: true,
                            message: 'Colaborador convidado com sucesso! Email enviado com senha provisória.'
                        });
                    }
                );
            });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Change Password
app.post('/api/auth/change-password', (req, res) => {
    const { email, oldPassword, newPassword } = req.body;
    const now = new Date().toISOString();

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        if (user.password !== oldPassword) {
            return res.status(401).json({ error: 'Senha atual incorreta.' });
        }

        db.run('UPDATE users SET password = ?, updated_at = ? WHERE email = ?',
            [newPassword, now, email],
            function (err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, message: 'Senha alterada com sucesso!' });
            }
        );
    });
});

// Contact Form
app.post('/api/contact', async (req, res) => {
    const { name, email, message } = req.body;

    // Log the contact message to console
    console.log('\n📧 NOVA MENSAGEM DE CONTATO:');
    console.log(`Nome: ${name}`);
    console.log(`Email: ${email}`);
    console.log(`Mensagem: ${message}`);
    console.log(`Data: ${new Date().toLocaleString('pt-BR')}\n`);

    try {
        // Try to send email if configured
        if (process.env.EMAIL_PASS) {
            await transporter.sendMail({
                from: process.env.EMAIL_USER || 'wesleypaulinocoelho@gmail.com',
                to: 'wesleypaulinocoelho@gmail.com',
                replyTo: email,
                subject: 'Contato - Avaliação de Clima',
                html: `
                    <h2>Nova Mensagem de Contato</h2>
                    <p><strong>Nome:</strong> ${name}</p>
                    <p><strong>Email:</strong> ${email}</p>
                    <p><strong>Mensagem:</strong></p>
                    <p>${message}</p>
                    <hr>
                    <p><small>Enviado em: ${new Date().toLocaleString('pt-BR')}</small></p>
                `
            });
            console.log('✅ Email enviado com sucesso!');
        } else {
            console.log('⚠️  Email não configurado. Mensagem registrada apenas no console.');
        }

        res.json({ success: true, message: 'Mensagem registrada! O administrador entrará em contato em breve.' });
    } catch (error) {
        console.error('⚠️  Erro ao enviar email (não crítico):', error.message);
        // Still return success - message was logged
        res.json({ success: true, message: 'Mensagem registrada! O administrador entrará em contato em breve.' });
    }
});

// Get all surveys (filtered by user + shared with collaborators)
app.get('/api/surveys', (req, res) => {
    const userId = req.headers['x-user-id'];

    if (!userId) {
        return res.status(401).json({ error: 'Usuário não autenticado' });
    }

    // First, get user info to check if they're a collaborator
    db.get('SELECT owner_id FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        let query;
        let params;

        if (user.owner_id) {
            // User is a collaborator - show owner's surveys
            query = "SELECT * FROM surveys WHERE manager_id = ? ORDER BY created_at DESC";
            params = [user.owner_id];
        } else {
            // User is owner - show their surveys + surveys from collaborators
            query = `SELECT DISTINCT s.* FROM surveys s 
                     LEFT JOIN users u ON s.manager_id = u.id 
                     WHERE s.manager_id = ? OR u.owner_id = ? 
                     ORDER BY s.created_at DESC`;
            params = [userId, userId];
        }

        db.all(query, params, (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    });
});

// Create survey
app.post('/api/surveys', (req, res) => {
    const { title, description, manager_id } = req.body;
    const id = Math.random().toString(36).substring(2, 15);
    const unique_link = Math.random().toString(36).substring(2, 15);
    const now = new Date().toISOString();

    db.run(`INSERT INTO surveys (id, title, description, status, unique_link, created_at, updated_at, manager_id) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, title, description, 'draft', unique_link, now, now, manager_id],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id, title, description, status: 'draft', unique_link, created_at: now, updated_at: now, manager_id });
        }
    );
});

// Update survey status
app.patch('/api/surveys/:id/status', (req, res) => {
    const { status } = req.body;
    const { id } = req.params;
    const now = new Date().toISOString();

    db.run(`UPDATE surveys SET status = ?, updated_at = ? WHERE id = ?`,
        [status, now, id],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

// Delete survey
app.delete('/api/surveys/:id', (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM surveys WHERE id = ?`, [id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Get survey by link
app.get('/api/surveys/link/:link', (req, res) => {
    const { link } = req.params;
    db.get(`SELECT * FROM surveys WHERE unique_link = ? AND status = 'active'`, [link], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row || null);
    });
});

// Get responses for a survey
app.get('/api/surveys/:id/responses', (req, res) => {
    const { id } = req.params;
    db.all(`SELECT * FROM survey_responses WHERE survey_id = ? ORDER BY submitted_at DESC`, [id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        // Parse answers JSON
        const parsedRows = rows.map((row) => ({
            ...row,
            answers: JSON.parse(row.answers)
        }));
        res.json(parsedRows);
    });
});

// Submit response
app.post('/api/responses', (req, res) => {
    const { survey_id, answers } = req.body;
    const id = Math.random().toString(36).substring(2, 15);
    const now = new Date().toISOString();

    db.run(`INSERT INTO survey_responses (id, survey_id, answers, submitted_at) VALUES (?, ?, ?, ?)`,
        [id, survey_id, JSON.stringify(answers), now],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

// AI Proxy Route
app.post('/api/ai/chat', async (req, res) => {
    const { messages, surveyData, mode } = req.body;
    const apiKey = process.env.VITE_OPENAI_API_KEY || process.env.OPENAI_API_KEY;

    if (!apiKey) {
        return res.status(500).json({ error: 'OpenAI API Key not configured' });
    }

    try {
        let systemPrompt = `Você é um Consultor Sênior em Desenvolvimento Organizacional e Engajamento (People Analytics), atuando como um parceiro estratégico para a liderança.

    Contexto da Pesquisa:
    ${surveyData ? `
    - Total de respostas: ${surveyData.totalResponses}
    - Satisfação geral: ${surveyData.overallSatisfaction}%
    - Taxa de resposta: ${surveyData.responseRate || 'N/A'}%
    
    Detalhes por Categoria:
    ${surveyData.questionScores?.map((q) => `- ${q.question}: ${q.score}% (${q.responses} respostas)`).join('\n') || 'N/A'}
    
    Intenção de Permanência:
    ${surveyData.permanenceData?.map((p) => `- ${p.name}: ${p.value}`).join('\n') || 'N/A'}
    
    Principais Comentários (Amostra):
    ${Object.entries(surveyData.writtenAnswers || {}).map(([key, values]) => `${key}: ${values.slice(0, 3).join('; ')}`).join('\n') || 'Nenhum comentário'}
    ` : 'Aguardando dados da pesquisa.'}

    Suas diretrizes fundamentais:
    1. **Seja um Especialista**: Não dê respostas genéricas. Use termos da área (ex: eNPS, turnover voluntário, segurança psicológica, employee experience) quando apropriado, mas explique-os de forma clara.
    2. **Baseie-se nos Dados**: Sempre cite os números específicos da pesquisa para justificar suas recomendações. Por exemplo: "Como a satisfação com Liderança está em 60%, sugiro..." em vez de apenas "Melhore a liderança".
    3. **Conversa Natural e Empática**: Aja como um consultor humano conversando com um gestor preocupado. Use frases como "Entendo sua preocupação", "Um ponto que me chamou a atenção nos dados foi...", "Olhando para os comentários, percebo que...".
    4. **Foco em Ação**: Para cada problema identificado, sugira uma ação prática (Quick Win) e uma estrutural.
    5. **Formatação**: Use negrito (**texto**) para destacar pontos chaves e métricas. Use listas para facilitar a leitura.
    `;

        if (mode === 'analysis') {
            systemPrompt += `
      
      TAREFA: Gere um RELATÓRIO EXECUTIVO COMPLETO E DETALHADO da pesquisa de clima.
      
      O relatório deve ser formatado em Markdown e conter as seguintes seções:
      1. **Resumo Executivo**: Visão geral rápida dos principais achados.
      2. **Análise de Indicadores Chave**: Interpretação profunda dos scores de satisfação e categorias.
      3. **Análise Qualitativa**: Insights baseados nos comentários e feedbacks escritos.
      4. **Identificação de Riscos**: Pontos de atenção crítica e potenciais impactos no negócio (turnover, produtividade).
      5. **Plano de Ação Recomendado**:
         - Ações Imediatas (Quick Wins)
         - Ações Estruturais (Médio/Longo Prazo)
      6. **Conclusão**: Mensagem final encorajadora para a liderança.

      Seja rigoroso na análise e criativo nas soluções. O relatório deve estar pronto para ser impresso e apresentado à diretoria.
      `;
        } else {
            systemPrompt += `
      
      TAREFA: Você é um chatbot consultor especializado. Sua missão é responder perguntas sobre a pesquisa de clima de forma PRECISA e BASEADA EM DADOS.
      
      REGRAS CRÍTICAS:
      
      0. **NUNCA REPITA A PERGUNTA DO USUÁRIO**:
         - NÃO comece sua resposta repetindo o que o usuário perguntou.
         - Vá DIRETO à resposta.
         - ERRADO: "Qual o ponto mais fraco? O ponto mais fraco é..."
         - CERTO: "O ponto mais fraco é **Oportunidades de Crescimento** com 40%."
      
      1. **ANALISE OS DADOS ANTES DE RESPONDER**:
         - Quando perguntarem "qual o ponto mais fraco", você DEVE comparar todos os scores e identificar o MENOR.
         - Quando perguntarem "qual o ponto mais forte", você DEVE identificar o MAIOR score.
         - NÃO diga "todas as categorias estão iguais" se houver diferenças nos scores.
      
      2. **SEJA ESPECÍFICO E DIRETO**:
         - Responda a pergunta EXATA que foi feita.
         - Se perguntarem "qual", identifique UMA categoria específica.
         - Se perguntarem "por que", explique causas baseadas nos comentários.
         - Se perguntarem "o que fazer", dê ações concretas.
      
      3. **USE OS DADOS REAIS**:
         - Cite o score exato: "A Relação com Liderança está em **60%**"
         - Mencione comentários relevantes quando disponíveis
         - Compare com outras categorias quando apropriado
      
      4. **FORMATO DA RESPOSTA**:
         - Primeira frase: Resposta direta à pergunta
         - Segundo parágrafo: Dados que justificam
         - Terceiro parágrafo (se aplicável): Recomendação de ação
      
      EXEMPLOS DE BOAS RESPOSTAS:
      
      Pergunta: "Qual o ponto mais fraco?"
      Resposta: "O ponto mais fraco é **Oportunidades de Crescimento** com apenas **40%** de satisfação. Este é o score mais baixo entre todas as categorias avaliadas.
      
      Baseado nos comentários, os colaboradores mencionam falta de clareza sobre planos de carreira e poucas oportunidades de desenvolvimento.
      
      **Recomendação**: Criar um programa estruturado de desenvolvimento individual (PDI) e comunicar claramente as trilhas de carreira disponíveis."
      
      Pergunta: "O que fazer sobre comunicação interna?"
      Resposta: "A Comunicação Interna está em **60%**, indicando espaço para melhoria. Sugiro duas ações:
      
      **Quick Win**: Implementar um canal de comunicação semanal (newsletter ou reunião) para manter todos alinhados.
      **Ação Estrutural**: Criar um fluxo de comunicação transparente onde decisões importantes sejam compartilhadas com antecedência."
      
      NUNCA faça respostas genéricas ou vagas. Sempre cite números e seja específico.
      `;
        }

        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: systemPrompt },
                    ...messages
                ],
                temperature: 0.7,
                max_tokens: mode === 'analysis' ? 2500 : 1000,
            }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error?.message || 'Erro na API da OpenAI');
        }

        const data = await response.json();
        res.json({ content: data.choices[0].message.content });

    } catch (error) {
        console.error('AI Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Rota TEMPORÁRIA para configurar o Master Admin
app.get('/api/setup-master-init', (req, res) => {
    const ADMIN_EMAIL = 'wesleypaulinocoelho@gmail.com';
    const ADMIN_PASSWORD = 'Admin2024!';
    const now = new Date().toISOString();
    const adminId = 'admin-master-001';

    // Verificar se já existe
    db.get('SELECT * FROM users WHERE email = ?', [ADMIN_EMAIL], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (user) {
            // Se existe, atualiza para ser ativo e admin
            db.run('UPDATE users SET password = ?, status = ?, role = ?, updated_at = ? WHERE email = ?',
                [ADMIN_PASSWORD, 'active', 'admin', now, ADMIN_EMAIL],
                function (err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, message: 'Usuário Master Admin ATUALIZADO com sucesso! Tente logar agora.' });
                }
            );
        } else {
            // Se não existe, cria
            db.run(`INSERT INTO users (id, email, password, status, role, created_at, updated_at) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [adminId, ADMIN_EMAIL, ADMIN_PASSWORD, 'active', 'admin', now, now],
                function (err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, message: 'Usuário Master Admin CRIADO com sucesso! Tente logar agora.' });
                }
            );
        }
    });
});

// Handle React routing, return all requests to React app
app.get('*', (req, res) => {
    res.sendFile(join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


