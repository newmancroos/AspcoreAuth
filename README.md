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
<p>
	<h3>Authorization</h3>
	In .Net core autorization the default authorization policy is the user should get authenticated<br> we override our own default authorization plolicy. <br>
	
	<pre>
	        services.AddAuthorization(config =&gt;
            {
                var defaultAuthBuilder = new AuthorizationPolicyBuilder();
                var defaultAuthPolicy = defaultAuthBuilder
                .RequireAuthenticatedUser()
                .RequireClaim(ClaimTypes.DateOfBirth)
                .Build();

                config.DefaultPolicy = defaultAuthPolicy;
            });
	</pre>
	if you don't have claim of type DataBirth then we'll get access denied page.
	this is what defaultly happen.
	<br>
	We can directly use authorization using attribute like
	<b>[Authorize(Role="Admin")]</b> or
	<b>[Authorize(Policy="SomePolicy")]  //It may be built-in policy or custom policy
	or Using <b>IAuthorizationService</b> <br>
	we can implement authorization.
	<br>
</p>
<p>
	<ul>
		<li>
			<h3>IAuthorizationService</h3><br>
			If you want to authorize a user inbetween a proess, that means if you want to implement authorization check middle of the process, <br>
			we can inject IAuthorizationService and using it to check the authorization.
			ex.:
			<pre>
				 public async Task<IActionResult> DoStuff() {
					//Do any stuff here

					var builder = new AuthorizationPolicyBuilder("Schema");
					var customPolicy = builder.RequireClaim("Hello").Build();
					var authResult = await _authorizationService.AuthorizeAsync(User, customPolicy);
					if (authResult.Succeeded)
					{ 
						//Authorization success
					}
					
					//await _authorizationService.AuthorizeAsync(User, "Claim.DoB");  //  Constructor Injection
					return View("Index");
				}
			</pre><br>
			We can alos doign the same in the MVC View.<br>
			We can also inject IAuthorizationService in function level<br>
			ex.:
			<pre>
			        public async Task<IActionResult> DoStuff_FuncInject([FromServices] IAuthorizationService authService)
					{
						//Do any stuff here

						var builder = new AuthorizationPolicyBuilder("Schema");
						var customPolicy = builder.RequireClaim("Hello").Build();
						var authResult = await authService.AuthorizeAsync(User, customPolicy);
						if (authResult.Succeeded)
						{
							return View("Index");
						}

						//await _authorizationService.AuthorizeAsync(User, "Claim.DoB");
						return View("Index");
					}
			</pre>
		</li>
		<li>
			<h3>Global Authorization filter</h3><br>
			When we create a filter in the startup.cs or customfilter, we want to use it as attribute in the controller function. But what if I want to appliy a filter for all controller function globally?, for that we have global policy...<br>
			<pre>
				//This is global filter, will added to all controller methods. If you want to bypass need to add [AllowAnonymous] atribute
				//This you can directly write in startup.cs or use filters.
				services.AddControllersWithViews(config =>
				{
					var defaultAuthBuilder = new AuthorizationPolicyBuilder();
					var defaultAuthPolicy = defaultAuthBuilder

					//If I add Database claim, it will thro Access denied even in Index page
					//.RequireClaim(ClaimTypes.DateOfBirth)
					.RequireAuthenticatedUser()
					.Build();

					config.Filters.Add(new AuthorizeFilter(defaultAuthPolicy));
				});
			</pre>
		</li>
		<li>
			<h3>OperationAuthorizationRequirement</h3><br>
			it is also kind of Authorization Requirement but this we can use as a check point in any opertion for checking users permission
			<pre>
				
			</pre>
		</li>
	</ul>
</p>
