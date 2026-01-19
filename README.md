# WP Recover & Reinstall Script

**[English]** | [Português](#português)

## English

### Overview
This is a single-file PHP script designed to help recover compromised WordPress sites. It automates the process of cleaning core files, reinstalling a fresh copy of WordPress, and performing a basic security scan on your content.

### Features
*   **Core Cleanup**: Deletes `wp-admin`, `wp-includes`, and root PHP files to remove potential backdoors.
    *   *Note: `wp-config.php` is preserved.*
*   **Auto-Reinstall**: Downloads or extracts the latest WordPress version directly from wordpress.org.
*   **Security Scan**: Scans `wp-content` for suspicious files (PHP in uploads, 777 permissions, obfuscated code).
*   **User Interface**: Modern, dark-themed UI with a real-time progress bar.

### How to Use
1.  **Backup**: IMPORTANT! Make sure you have a backup of your `wp-config.php` and database.
2.  **Upload**: Upload `wp-recover.php` to the root folder of your website (public_html or www).
3.  **Run**: Open your browser and go to `https://yourdomain.com/wp-recover.php`.
4.  **Start**: Click "Start Recovery Process".
5.  **Review**: Check the scan report at the bottom of the page.
6.  **Finish**: Delete `wp-recover.php` after you are done!

---

## <a name="português"></a>Português

### Visão Geral
Este é um script PHP de arquivo único projetado para ajudar a recuperar sites WordPress comprometidos. Ele automatiza o processo de limpeza dos arquivos principais (core), reinstala uma cópia limpa do WordPress e executa uma verificação de segurança básica no seu conteúdo.

### Funcionalidades
*   **Limpeza do Core**: Exclui `wp-admin`, `wp-includes` e arquivos PHP da raiz para remover possíveis backdoors.
    *   *Nota: O arquivo `wp-config.php` é preservado.*
*   **Auto-Reinstalação**: Baixa ou extrai a versão mais recente do WordPress diretamente do wordpress.org.
*   **Verificação de Segurança**: Escaneia a pasta `wp-content` em busca de arquivos suspeitos (arquivos PHP em uploads, permissões 777, código ofuscado).
*   **Interface**: UI moderna e escura com barra de progresso em tempo real.

### Como Usar
1.  **Backup**: IMPORTANTE! Certifique-se de ter um backup do seu `wp-config.php` e do banco de dados.
2.  **Upload**: Envie o arquivo `wp-recover.php` para a pasta raiz do seu site (public_html ou www).
3.  **Executar**: Abra seu navegador e acesse `https://seudominio.com/wp-recover.php`.
4.  **Iniciar**: Clique em "Start Recovery Process" (Iniciar Processo de Recuperação).
5.  **Revisar**: Verifique o relatório de varredura na parte inferior da página.
6.  **Finalizar**: Exclua o arquivo `wp-recover.php` quando terminar!

---

### Disclaimer / Aviso
**Use at your own risk. / Use por sua conta e risco.**
This script deletes files. The author is not responsible for any data loss.
Este script exclui arquivos. O autor não se responsabiliza por qualquer perda de dados.
