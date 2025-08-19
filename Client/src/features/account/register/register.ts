import { Component, inject, input, output, signal } from '@angular/core';
import { RegisterCreds, User } from '../../../types/user';
import { FormsModule } from "@angular/forms";
import { AccountService } from '../../../core/services/account-service';

@Component({
  selector: 'app-register',
  imports: [FormsModule],
  templateUrl: './register.html',
  styleUrl: './register.css'
})
export class Register {
  private accountService = inject(AccountService);
  protected creds = {} as RegisterCreds;
  cancelRigester = output<boolean>();
  

  register(){
    this.accountService.register(this.creds).subscribe({
      next: response => {
        console.log(response);
        this.cancel();
      },
      error: error => console.log(error) 
    })
  }

  cancel() {
    this.cancelRigester.emit(false)
  }
}
