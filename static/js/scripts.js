function toggleVisibility(id1, id2) {
    var x1 = document.getElementById(id1);
    var x2 = document.getElementById(id2);

    if (x1.type === "password") {
        x1.type = "text";
        x2.innerText = "visibility_off";
    } else {
        x1.type = "password";
        x2.innerText = "visibility";
    }
}

function hideUnhide(doc) {
    if (doc.style.display === "none") {
        doc.style.display = "initial";
    } else {
        doc.style.display = "none";
    }
}

function deleteUser(){
    var form = document.getElementById('deleteUser');
    form.submit();
}

function editAccount(idx) {
    let account = document.getElementById('account' + idx);
    let username = document.getElementById('username' + idx);
    let password = document.getElementById('password' + idx);

    account.innerHTML = `<input type="text" class="form-control" id="tableInputAcc${idx}" name="account" value="${account.innerText}" required />`;
    username.innerHTML = `<input type="text" class="form-control" id="tableInputUser${idx}" name="email" value="${username.innerText}" required />`;
    password.innerHTML = `<input type="text" class="form-control" id="tableInputPaswd${idx}" name="password" value="${password.innerText}" required />`;

    let edit = document.getElementById('edit' + idx);
    hideUnhide(edit);

    let add = document.getElementById('add' + idx);
    hideUnhide(add);
}

function editUsername(idx){
    let username = document.getElementById(idx);
    username.disabled = false;

    let edit = document.getElementById('edit_username');
    hideUnhide(edit);

    let add = document.getElementById('add_username');
    hideUnhide(add);
}

function updateAccount(idx, accountid) {
    let account = document.getElementById('tableInputAcc' + idx);
    let username = document.getElementById('tableInputUser' + idx);
    let password = document.getElementById('tableInputPaswd' + idx);

    console.log(account.value);
    console.log(username.value);
    console.log(password.value);

    $.ajax({
        url: "/update",
        type: 'POST',
        timeout: 0,
        headers: {
            "Content-Type": "application/json"
        },
        data: JSON.stringify({
            accountid: accountid,
            account: account.value,
            email: username.value,
            password: password.value
        }),
        success: function (data) {
            if (data.status == 'success') {
                account.parentElement.innerText = account.value;
                username.parentElement.innerText = username.value;
                password.parentElement.innerText = password.value;

                let edit = document.getElementById('edit' + idx);
                hideUnhide(edit);

                let add = document.getElementById('add' + idx);
                hideUnhide(add);
            } else {
                alert('Error');
            }
        }
    });
}

function updateUsername(idx) {
    let username = document.getElementById(idx);
    username.disabled = true;

    $.ajax({
        url: "/update_username",
        type: 'POST',
        timeout: 0,
        headers: {
            "Content-Type": "application/json"
        },
        data: JSON.stringify({
            username: username.value,
        }),
        success: function (data) {
            if (data.status == 'success') {
                window.location.reload();
            } else {
                alert('Error');
            }
        }
    });
}

function deleteAccount(accountid) {
    $.ajax({
        url: "/delete",
        type: 'POST',
        timeout: 0,
        headers: {
            "Content-Type": "application/json"
        },
        data: JSON.stringify({
            accountid: accountid
        }),
        success: function (data) {
            if (data.status == 'success') {
                window.location.reload();
            } else {
                alert('Error');
            }
        }
    });
}

function verifyAccount(){
    $.ajax({
        url: "/send_verification",
        type: 'GET',
        timeout: 0,
        headers: {
            "Content-Type": "application/json"
        },
        success: function (data) {
            if (data.status == 'success') {
                window.location.reload();
            } else {
                alert('Error');
            }
        }
    });
}