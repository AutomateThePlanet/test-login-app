$('#authTabs a').on('shown.bs.tab', function (e) {
    // Hide all inner authentication forms
    $('.auth-form').css('display', 'none');

    // Show the initial authentication form for the active tab
    const activeTab = e.target.getAttribute('aria-controls');
    $(`#${activeTab} .auth-form:first`).css('display', 'block');
});

$(document).ready(function () {
    $('.toast').toast();
});

// Function to show toast message
function showToast(message) {
    document.getElementById('toast-body').textContent = message;
    $('.toast').toast({ delay: 5000 });
    $('.toast').toast('show');
}

document.getElementById('passwordless-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const email = document.getElementById('email').value;

    fetch(`/auth/passwordless?email=${email}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('Login code has been sent to your email. Please check your inbox.');
                document.getElementById('passwordless-form').style.display = 'none';
                document.getElementById('verify-code-form').style.display = 'block'; // Show the code verification form
            } else {
                showToast('Failed to send login code. Please try again.');
            }
        });
});


document.getElementById('verify-code-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const code = document.getElementById('code').value;

    fetch('/auth/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('Code verified successfully. Logging you in.');
                window.location.href = data.redirectUrl; // Redirect to the profile page
            } else {
                showToast('Invalid code. Please try again.');
            }
        });
});

// Send SMS Code
document.getElementById('sms-auth-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const phoneNumber = document.getElementById('phoneNumber').value;

    fetch('/send-verification-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phoneNumber }),
    })
       // .then(response => response.json())
        .then(data => {
            document.getElementById('sms-auth-form').style.display = 'none';
            document.getElementById('verify-sms-code-form').style.display = 'block'; // Show the SMS code verification form
        });
});

// Verify SMS Code
document.getElementById('verify-sms-code-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const smsCode = document.getElementById('smsCode').value;

    fetch('/verify-sms-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: smsCode }),
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('SMS code verified successfully. Logging you in.');
                window.location.href = data.redirectUrl; // Redirect to the profile page
            } else {
                showToast('Invalid SMS code. Please try again.');
            }
        });
});

document.getElementById('login-form').addEventListener('submit', function (e) {
    e.preventDefault();

    const usernameOrEmail = document.getElementById('usernameOrEmail').value;
    const password = document.getElementById('password').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    const twoFaTokenElement = document.getElementById('twoFaToken');
    const twoFaTokenGroupElement = document.getElementById('2fa-token-group');
    const captchaResponse = grecaptcha.getResponse();
    const captchaBypass = document.querySelector('[name="captcha-bypass"]').value;

    let requestData = {
        usernameOrEmail: usernameOrEmail,
        password: password,
        rememberMe: rememberMe,
        captchaResponse: captchaResponse,     
        captchaBypass: captchaBypass        
    };

    console.log('email:', usernameOrEmail);
    console.log('password:', password);
    console.log('rememberMe:', rememberMe);

    // If the 2FA input field is visible, add the token to the request data
    if (twoFaTokenGroupElement.style.display !== 'none') {
        requestData.twoFaToken = twoFaTokenElement.value;
    }

    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestData),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Redirect to profile or dashboard
            window.location.href = data.redirectUrl || '/profile';
        } else {
            // If 2FA is required, display the 2FA input field to the user
            if (data.twoFaRequired) {
                twoFaTokenGroupElement.style.display = 'block';
                showToast('Please enter your 2FA token to proceed.');
            } else {
                showToast(data.message || 'Invalid login credentials.');
            }
        }
    });
});


// registration
document.getElementById('registration-form').addEventListener('submit', function (event) {
    event.preventDefault();

    // Get form data
    const usernameField = document.getElementById('registerUsername');
    const emailField = document.getElementById('registerEmail');
    const phoneField = document.getElementById('registerPhone');  // Fetch phone field
    const passwordField = document.getElementById('registerPassword');
    const confirmPasswordField = document.getElementById('confirmPassword');

    const username = usernameField.value;
    const email = emailField.value;
    const phone = phoneField.value;  // Get phone value
    const password = passwordField.value;
    const confirmPassword = confirmPasswordField.value;

    // Client-side Validations
    if (!/^[a-zA-Z0-9]{4,16}$/.test(username)) {
        return showToast('Username must be 4-16 characters long and contain only alphanumeric characters.');
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return showToast('Invalid email format.');
    }

    // Phone validation (assuming a simple regex; adjust as per requirements)
    if (!/^\+?[0-9]{10,15}$/.test(phone)) {
        return showToast('Invalid phone number format. Please include only numbers and it should be 10-15 digits long.');
    }

    if (password !== confirmPassword) {
        return showToast('Passwords do not match!');
    } else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{8,32})/.test(password)) {
        return showToast('Password must be 8-32 characters long and contain at least one uppercase letter, one lowercase letter, and one number.');
    }

    // Send registration data to server
    fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            email: email,
            phone: phone,  // Send phone value to server
            password: password,
            confirmPassword: confirmPassword
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Clear the form fields after successful registration
                usernameField.value = '';
                emailField.value = '';
                phoneField.value = '';  // Clear phone field
                passwordField.value = '';
                confirmPasswordField.value = '';

                showToast('Registration successful! Check your email for your activation code!');
            } else {
                showToast(data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('There was an error with the registration.');
        });
});

function activateUser() {
    const code = document.getElementById('activationCode').value;

    fetch('/activate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ activationCode: code })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('Activation successful!');
                // Redirect to login page or provide any other feedback
                window.location.href = '/index.html#loginAuth'; // Redirect to login page after successful activation
            } else {
                showToast(data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('There was an error with the activation.');
        });
}

// password reset
// Password Reset Request Logic
document.getElementById('password-reset-request-form').addEventListener('submit', function (event) {
    event.preventDefault();

    const email = document.getElementById('resetEmail').value;

    fetch('/request-password-reset', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: email })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                email.value = '';
                showToast('Password reset link sent to your email!');
            } else {
                showToast(data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('There was an error processing your request.');
        });
});

// Password Reset Logic
document.getElementById('password-reset-form').addEventListener('submit', function (event) {
    event.preventDefault();

    const newPassword = document.getElementById('newPassword').value;

    // Extract fragment from URL
    const fragment = window.location.hash.substring(1); // Get string after '#'

    // Check if fragment exists and contains the expected structure
    if (!fragment || !fragment.startsWith('passwordReset?')) {
        showToast('Invalid password reset link.');
        return;
    }

    // Extract token from fragment
    const fragmentParams = new URLSearchParams(fragment.split('?')[1]);
    const resetToken = fragmentParams.get('token');

    if (!resetToken) {
        showToast('Invalid password reset link.');
        return;
    }

    fetch('/password-reset', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ newPassword: newPassword, token: resetToken })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('Password reset successful!');
                window.location.href = '/index.html#loginAuth';
            } else {
                showToast(data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('There was an error resetting your password.');
        });
});


// change status 
document.getElementById('set-status-form').addEventListener('submit', function (event) {
    event.preventDefault();

    const email = document.getElementById('statusEmail').value;
    const status = document.getElementById('userStatus').value;

    fetch('/set-status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: email, status: status })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast('User status updated successfully!');
            } else {
                showToast(data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('There was an error updating the user status.');
        });
});


document.addEventListener('DOMContentLoaded', function () {
    let hash = window.location.hash;

    if (hash) {
        // Activate the tab
        $('.nav-tabs a[href="' + hash + '"]').tab('show');
    }
});

function resetDatabase() {
    fetch('/reset-db', { method: 'GET' })
        .then(response => response.text())
        .then(data => {
            // handle the response, maybe show a notification to the user
            console.log(data);
        });
}
