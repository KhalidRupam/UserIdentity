using Autofac;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UserIdentity.Data;

namespace UserIdentity
{
    public class WebModule: Module
    {
        protected override void Load(ContainerBuilder builder)
        {
            

            builder.RegisterType<ApplicationDbContext>().As<IApplicationDbContext>()
               .InstancePerLifetimeScope();
            base.Load(builder);
        }
    }
}
