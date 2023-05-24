<#import "template.ftl" as layout>

<@layout.registrationLayout; section>
    <#if section = "form">
        <h1>Verification Code: ${verification_code}</h1>
        <p>Please ensure that the verification code on this website and your Smart-ID matches and confirm your login via the Smart-ID app.</p>

        <form id="kc-smartid-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post"></form>
    </#if>
</@layout.registrationLayout>

<script type="application/javascript">
    document.getElementById('kc-smartid-login-form').submit();
</script>