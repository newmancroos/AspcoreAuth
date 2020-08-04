# AspcoreAuth

<ul>
	<li>
		There is a mail kit nuget package <b>NetCore.MailKit</b> to send email in asp.net core project
	</li>
</ul><br>
<h3>Steps involved in implement email confirmation when registering</h3>
<ol>
	<li>Install NetCore.mailKit nuget package</li>
	<li>In Startup.cs, in services.AddIdentity add config.SignIn.RequiredConfirmedEmail = true;</li>
	<li>
		
		Add <b>Email</b> block in <b>appSetting.json</b> <br>
		<pre>
			"Email": {
			"Server": "127.0.0.1",
			"Port": 25,
			"SenderName": "Newman",
			"SenderEmail" :  "Test@test.com"
			}
		</pre>
		In startup.cs we need to register Mailkit<br>
		<pre>
			var mailKitOptions = _config.GetSection("Email").Get<MailKitOptions>();
            services.AddMailKit(config => config.UseMailKit(mailKitOptions));
		</pre>
	</li>
	<li>
		Inject IEmailService where we send email in the registration user
	</li>
	<li>
		Using IEmailservice generate the code and send email
		<pre>
			var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
			var link = Url.Action(nameof(VerifyEmail),"Home",new {userId=user.Id, code }, Request.Scheme, Request.Host.ToString());
			await _emailService.SendAsync("test@test.com", "Email Verify", link);
			return RedirectToAction("EmailVerification");
		</pre>
	</li>
	<li>
		Since we installed <b>PaperCut</b> email dev client, that will notify you a email received, you can click the link on it.
	</li>
	<li>
		Validate the code from the link cliked
		<pre>
			 var user =await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest();
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
            {
                return View();
            }
            else
            {
                return BadRequest();
            }
		</pre>
	</li>
</ol>
<hr/>