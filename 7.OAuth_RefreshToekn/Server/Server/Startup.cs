using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace Server
{
    public class Startup
    {
       public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication("OAuth")
                .AddJwtBearer("OAuth", config => {
                    var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
                    var key = new SymmetricSecurityKey(secretBytes);

                    //----------------------------------------------------------------------------------
                    //If we want to pass Bearer token in url we can validate the token here
                    //using JwtBeaererEvents. If yo want to pass it as header you don't need these block here
                    config.Events = new JwtBearerEvents()
                    {
                        OnMessageReceived = context => {
                            if (context.Request.Query.ContainsKey("access_token")) {

                                context.Token = context.Request.Query["access_token"];
                            }
                            return Task.CompletedTask;
                        }
                    };
                    //----------------------------------------------------------------------------------
                    config.TokenValidationParameters = new TokenValidationParameters()
                    {
                        // Setting expire of Jwt token in 1 millisecond is not working becasue the default is 5 minute. 
                        //so making ClockSkew makes immidiate apply of the expire time. This will force to expire in 1 millisecond as we configure in 
                        //Token method
                        ClockSkew = TimeSpan.Zero, 
                        ValidIssuer = Constants.Issuer,
                        ValidAudience = Constants.Audiance,
                        IssuerSigningKey = key,
                    };
                });
            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
