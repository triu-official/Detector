document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('analyze-form');
  const spinner = document.getElementById('submit-spinner');
  if (form && spinner) {
    form.addEventListener('submit', function () {
      spinner.classList.remove('d-none');
    });
  }
});
