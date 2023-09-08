const authCookie = document.cookie.split('; ').find(row => row.startsWith('auth='));
const userIdCookie = document.cookie.split('; ').find(row => row.startsWith('userId='));

if (authCookie && userIdCookie) {
    const authValue = authCookie.split('=')[1];

    // Send the auth cookie value to the server for validation and data retrieval
    fetch('/api/verify-auth-cookie', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${authValue}`
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success !== false) {
                // Update the UI
                document.getElementById('username').textContent = data.displayName;
                document.getElementById('provider').textContent = data.provider;
            } else {
                console.error(data.message);
                window.location.href = "/";
            }
        })
        .catch(error => {
            console.error('Error:', error);
            window.location.href = "/";
        });
} else {
    window.location.href = "/";
}

$(document).ready(function () {
    $('.toast').toast();
});

$(document).ready(() => {
    // Fetch current user's profile data
    fetch('/get-profile')
        .then(response => response.json())
        .then(data => {
            console.log('et-profile: ' + data);

            // Fill the form fields with user data
            $('#editUsername').val(data.username);
            $('#editEmail').val(data.email);
            $('#editPhoneNumber').val(data.phone);
            // You typically wouldn't prefill the password for security reasons
            // If the user wishes to update it, they can type a new one.
        })
        .catch(error => {
            showToast('Error fetching profile:', error);
        });

    // Listen to form submission
    $('#edit-user-form').submit(function (e) {
        e.preventDefault();

        const updatedData = {
            username: $('#editUsername').val(),
            email: $('#editEmail').val(),
            phoneNumber: $('#editPhoneNumber').val(),
            password: $('#editPassword').val(),
        };

        fetch('/update-profile', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(updatedData),
        })
            .then(response => response.text())
            .then(message => {
                showToast(message);  // Inform user about the update result
            })
            .catch(error => {
                showToast('Error updating profile:' + error);
            });
    });
});

function showToast(message) {
    $("#toast-body").text(message);
    $(".toast").toast({ delay: 5000 });
    $(".toast").toast('show');
}

function revokeGoogleAccess() {
    // Placeholder for revoking Google access, adjust as needed
    fetch('/revoke-google').then(response => {
        document.getElementById('revoked-alert').style.display = 'block';
    });
}

function revokeFacebookAccess() {
    // Placeholder for revoking Facebook access, adjust as needed
    fetch('/revoke-facebook').then(response => {
        document.getElementById('revoked-alert').style.display = 'block';
    });
}

function resetDatabase() {
    fetch('/reset-db', { method: 'GET' })
        .then(response => response.text())
        .then(data => {
            // handle the response, maybe show a notification to the user
            console.log(data);
        });
}

$(document).ready(function () {
    // Initially check if the user has 2FA enabled
    check2FAStatus();

    $("#setup-2fa-btn").click(function() {
        initiate2FA();
    });

    $("#verify-2fa-btn").click(function() {
        const token = $("#token").val();
        if (!token) {
            showToast("Please enter a token!");
            return;
        }
        verify2FAToken(token);
    });

    $("#disable-2fa-btn").click(function() {
        disable2FA();
    });
});

function check2FAStatus() {
    $.ajax({
        url: "/2fa/status",
        method: "GET",
        success: function(data) {
            if (data.enabled) {
                $("#2fa-status .badge").text("Enabled").removeClass("badge-secondary").addClass("badge-success");
                $("#setup-2fa-btn").hide();
                $("#2fa-enabled").show();
            } else {
                $("#2fa-status .badge").text("Disabled");
            }
        },
        error: function(error) {
            showToast("Error fetching 2FA status.");
        }
    });
}

function initiate2FA() {
    $.ajax({
        url: "/2fa/initiate",
        method: "GET",
        success: function(data) {
            if (data.qrcode) {
                $("#qrcode").attr("src", data.qrcode);
                $("#2fa-setup").show();
            } else {
                showToast("Error generating QR code.");
            }
        },
        error: function(error) {
            showToast("Error initiating 2FA.");
        }
    });
}

function verify2FAToken(token) {
    console.log('verify token: ' + token);

    $.ajax({
        url: "/2fa/verify",
        method: "POST",
        contentType: "application/json",
        data: JSON.stringify({ token: token }),
        success: function(data) {
            if (data.verified) {
                showToast("2FA enabled successfully!");
                $("#2fa-status .badge").text("Enabled").removeClass("badge-secondary").addClass("badge-success");
                $("#2fa-setup").hide();
                $("#2fa-enabled").show();
            } else {
                showToast("Invalid token. Please try again.");
            }
        },
        error: function(error) {
            showToast("Error verifying token.");
        }
    });
}

function disable2FA() {
    $.ajax({
        url: "/2fa/disable",
        method: "POST",
        success: function(data) {
            if (data.disabled) {
                showToast("2FA disabled successfully!");
                $("#2fa-status .badge").text("Disabled").addClass("badge-secondary").removeClass("badge-success");
                $("#2fa-enabled").hide();
                $("#setup-2fa-btn").show();
            } else {
                showToast("Error disabling 2FA.");
            }
        },
        error: function(error) {
            showToast("Error while trying to disable 2FA.");
        }
    });
}